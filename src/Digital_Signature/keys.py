
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
        if not isinstance(value, (Path, str)):
            raise TypeError(f"Expected Path or str, got {type(value).__name__}")

        self._path = Path(value)


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

        # os.open return a file descriptor. Wich represents the open file at OS level 
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(key)
            except:
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
        
        except ValueError as e:
            raise ValueError("Incorrect password.") from e
        
        finally:
            for i in range(len(password)):
                password[i] = 0

    def get_public_key(self) -> bytes:
        private_key = self.load_key()
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

