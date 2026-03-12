from pathlib import Path
import secrets
from header import FileHeader


class CipherEngine:
    def __init__(self, key, cipher, cipher_id):
        self.key = key
        self.cipher = cipher
        self.cipher_id = cipher_id

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

            with open(output_path, "wb") as output_file:
                output_file.write(header.pack())
                output_file.write(input_path.name.encode("utf-8"))

            return output_path
        except Exception :
            if output_path.exists():
                output_path.unlink(missing_ok=True)
            raise
