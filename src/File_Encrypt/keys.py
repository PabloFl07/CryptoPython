import os
import secrets
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from pathlib import Path

from abc import ABC, abstractmethod


class KeyManager:
    _KEY_LENGTH = 32
    _DEFAULT_MTIME_TOL = 24 * 60 * 60  # 4 horas
    _ITERATIONS = 600000

    _DEFAULT_KEY_DIR = Path.home() / ".secret"
    _DEFAULT_KEY_FILE = _DEFAULT_KEY_DIR / "secret.key"

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):

        if not isinstance(value, Path):
            if not isinstance(value, str):
                raise TypeError("Cannot convert non-str type to Path")
            raise TypeError("")  # ! Dont even know what to say

        if value.is_dir():
            raise ValueError("Path must be a file, not a directory")

        self._path = value

    def __init__(self, path: Path = None):

        self.path = Path(path) if path else KeyManager._DEFAULT_KEY_FILE

    def generate_key(self, force: bool = False) -> bool:

        if self.path.exists() and not force:
            raise FileExistsError(
                f"Key `{self.path.name}` already exists at `{self.path.parent}` | Use --force to overwrite."
            )

        # Crear directorio con permisos 700
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)

        key = secrets.token_bytes(32)

        # Escribir archivo y ajustar permisos inmediatamente
        self.path.write_bytes(key)
        self.path.chmod(0o600)

        return self.path

    def load_key(self) -> bytes:

        if not self.path.exists():
            raise FileNotFoundError(f"Couldnt find key file: {self.path}")

        # Verificación de rotación (mtime)
        mtime = self.path.stat().st_mtime
        if (time.time() - mtime) > self._DEFAULT_MTIME_TOL:
            print(
                f"Warning: Key '{self.path.name}' is older than {self._DEFAULT_MTIME_TOL // 3600}h. Consider rotating it."
            )

        key = self.path.read_bytes()
        self.validate_key(key)
        return key

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KeyManager._ITERATIONS,
        )
        return kdf.derive(password.encode())

    @staticmethod
    def validate_key(key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")

        if len(key) != 32:
            raise KeyError(
                f"Invalid length. Expected: {len(key)}"
            )  # ! Add custom error


class KeySource(ABC):
    @abstractmethod
    def get_key(self, existing_salt: bytes | None = None) -> bytes: ...

    @abstractmethod
    def get_salt(self) -> bytes: ...


class PasswordSource(KeySource):
    def __init__(self, password: str):
        self._salt = secrets.token_bytes(32)
        self._password = password

    def get_key(self, existing_salt: bytes | None = None):
        salt = existing_salt if existing_salt is not None else self._salt
        return KeyManager.derive_key(self._password, salt)

    def get_salt(self):
        return self._salt


class FileSource(KeySource):
    def __init__(self, path: Path):
        self._manager = KeyManager(path)

    def get_key(self, existing_salt: bytes | None = None) -> bytes:
        return self._manager.load_key()

    def get_salt(self) -> bytes:
        return b"\x00" * 32
