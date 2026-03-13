from pathlib import Path
import secrets
from header import FileHeader
from cryptography.exceptions import InvalidTag
import hashlib


class CipherEngine:
    CHUNK_SIZE = 1024 * 64  # 64KB

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
        input_file: open,
        output_file: open,
        nonce_salt: bytes,
        file_name: str,
        transform,
        is_decrypt: bool = False,
    ):
        chunk_number = 0
        read_size = self.CHUNK_SIZE + (16 if is_decrypt else 0)
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
        if not input_path.exists():
            raise FileNotFoundError(f"No existe: {input_path}")

        output_path = output_path if output_path else input_path.with_suffix(".enc")

        nonce_salt = secrets.token_bytes(32)

        try:
            header = FileHeader(
                self.cipher_id, nonce_salt, password_salt, len(input_path.name)
            )

            with (
                open(input_path, "rb") as input_file,
                open(output_path, "wb") as output_file,
            ):
                output_file.write(header.pack())
                output_file.write(input_path.name.encode("utf-8"))

                self.process_chunk(
                    input_file,
                    output_file,
                    nonce_salt,
                    input_path.name,
                    self.cipher.encrypt,
                )

            return output_path
        except Exception:
            if output_path.exists():
                output_path.unlink(missing_ok=True)
            raise

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
