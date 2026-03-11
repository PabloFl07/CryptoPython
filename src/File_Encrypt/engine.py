from pathlib import Path
import secrets
from header import FileHeader


class CipherEngine:
    def __init__(self, key, cipher, cipher_id):
        self.key = key
        self.cipher = cipher
        self.cipher_id = cipher_id

    def encrypt_file(
        self, file_path: Path, output_path: Path = None, password_salt: bytes = None
    ):
        if not file_path.exists():
            raise FileNotFoundError(f"No existe: {file_path}")

        out_p = output_path if output_path else file_path.with_suffix(".enc")

        nonce_salt = secrets.token_bytes(32)

        try:
            header = FileHeader(
                self.cipher_id, nonce_salt, password_salt, len(file_path.name)
            )

            with open(out_p, "wb") as f_out:
                f_out.write(header.pack())
                f_out.write(file_path.name.encode("utf-8"))

            return out_p
        except Exception :
            if out_p.exists():
                out_p.unlink(missing_ok=True)
            raise
