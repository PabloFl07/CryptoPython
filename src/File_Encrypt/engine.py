"""
## Security Decision: file_name validation scope

**Context**
When decrypting, file_name is read directly from the encrypted file header and used to determine the output path.

**Decision**
We validate file_name only at encryption time (encrypt_file), not at decryption time.

**Rationale**
This tool is designed for personal use. The assumption is that every .enc file was produced by this tool, which already strips path components via Path(input_path).name before writing the header. Validating at decrypt would be redundant under this threat model.

**Consequences**
If a .enc file crafted by a third party (with a malicious file_name such as ../../.bashrc) is decrypted, the output could be written to an unintended path. This is an accepted risk given the personal-use scope. If the threat model changes — for example, if the tool is distributed or accepts files from external sources — sanitization must be added at the point where file_name is read from the header in run.py.
"""

from pathlib import Path
import secrets
from header import FileHeader
from cryptography.exceptions import InvalidTag
import hashlib
from typing import Callable


class CipherEngine:
    CHUNK_SIZE = 1024 * 64  # 64KB
    _TAG_SIZE = 16  # For AES-GCM and ChaCha20-Poly1305

    def __init__(self, key, cipher, cipher_id):
        self.key = key
        self.cipher = cipher
        self.cipher_id = cipher_id

    @staticmethod
    def derive_nonce(salt: bytes, chunk_number: int):
        return hashlib.blake2s(
            chunk_number.to_bytes(8, "big"), key=salt, digest_size=12
        ).digest()

    def process_chunk(
        self,
        input_file,
        output_file,
        nonce_salt: bytes,
        file_name: str,
        transform: Callable[[bytes, bytes, bytes], bytes],
        is_decrypt: bool = False,
    ):
        chunk_number = 0
        read_size = self.CHUNK_SIZE + (self._TAG_SIZE if is_decrypt else 0)
        buffer = bytearray(read_size)

        while bytes_read := input_file.readinto(buffer):
            chunk = bytes(memoryview(buffer)[:bytes_read])
            nonce = self.derive_nonce(nonce_salt, chunk_number)
            associated_data = (file_name + f":{chunk_number}").encode("utf-8")
            data = transform(nonce, chunk, associated_data)
            output_file.write(data)
            chunk_number += 1

    def encrypt_file(
        self, input_path: Path, output_path: Path = None, password_salt: bytes = None
    ):

        output_path = output_path or input_path.with_suffix(".enc")

        nonce_salt = secrets.token_bytes(32)

        file_name = input_path.name
        if not file_name or file_name in (".", ".."):
            raise ValueError(f"Invalid file name in path: {input_path}")

        try:
            header = FileHeader(
                self.cipher_id, nonce_salt, password_salt, len(file_name)
            )

            with (
                open(input_path, "rb") as input_file,
                open(output_path, "wb") as output_file,
            ):
                output_file.write(header.pack())
                output_file.write(file_name.encode("utf-8"))

                self.process_chunk(
                    input_file,
                    output_file,
                    nonce_salt,
                    file_name,
                    self.cipher.encrypt,
                )

            return output_path
        except FileNotFoundError:
            raise FileNotFoundError(f"File to encrypt not found: {input_path}")

    def decrypt_file(
        self, input_path: Path, output_path: Path, nonce_salt: bytes, file_name: str
    ):

        output_path = output_path or input_path.with_name(file_name + ".dec")
        data_offset = FileHeader.size() + len(file_name.encode("utf-8"))

        try:
            with (
                open(input_path, "rb") as input_file,
                open(output_path, "wb") as output_file,
            ):
                input_file.seek(data_offset)
                self.process_chunk(
                    input_file,
                    output_file,
                    nonce_salt,
                    file_name,
                    self.cipher.decrypt,
                    is_decrypt=True,
                )

            return output_path
        except InvalidTag:
            if output_path.exists():
                output_path.unlink(missing_ok=True)
            raise ValueError("Decryption failed: Invalid key or corrupted file.")
        except FileNotFoundError:
            raise FileNotFoundError(f"File to decrypt not found: {input_path}")
