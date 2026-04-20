
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from pathlib import Path
from getpass import getpass
import os


class KeyManager:

    _DEFAULT_KEY_DIR = Path.home() / "Dev" / "CryptoPython" / "keys" 
    _DEFAULT_KEY_FILE = _DEFAULT_KEY_DIR / "private.key"

    def __init__(self, path : Path = None):
        self.path = path or self._DEFAULT_KEY_FILE

    @property
    def path(self) -> Path:
        return self._path

    @path.setter
    def path(self, value):
        try:
            self._path = Path(value)
        except TypeError:
            raise TypeError(f"Expected a valid path object or string, got {type(value).__name__}")

    def generate_key(self) -> Path:
        if self.path.is_dir():
            raise ValueError("Path must be a file, not a directory")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)

        raw_key = Ed25519PrivateKey.generate()

        password = bytearray(getpass("Provide a password for the private key: ").encode("utf-8"))
        key = None

        try:
            key = bytearray(
                    raw_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(bytes(password)),
                )
            )

            # os.open returns a file descriptor. Which represents the open file at OS level 
            file_descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(file_descriptor, "wb") as f:
                    f.write(key)
            except Exception:
                os.close(file_descriptor)
                os.unlink(self.path)  
                raise
        finally:
            if key is not None:
                for i in range(len(key)):
                    key[i] = 0
            for i in range(len(password)):
                password[i] = 0

        return self.path

    def load_key(self):
        if self.path.is_dir():
            raise ValueError("Path must be a file, not a directory")
        if not self.path.exists():
            raise FileNotFoundError("Key File not found")
        

        password = bytearray(getpass("Provide the password to load the private key: ").encode("utf-8"))

        try:
            with open(self.path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=bytes(password),
            )

            return private_key
        
        except (ValueError, TypeError) as e:
            raise ValueError("Incorrect password or corrupted key file.") from e
        except UnsupportedAlgorithm as e:
            raise ValueError(f"Unsupported key type: {e}") from e
        
        finally:
            for i in range(len(password)):
                password[i] = 0

    def get_public_key(self):
        private_key = self.load_key()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return public_key

    def export_public_key(self, output_path : Path = None) -> Path:
        public_key = self.get_public_key()

        out = output_path or self.path.with_suffix(".pub")
        out.write_bytes(public_key)
        return out    


