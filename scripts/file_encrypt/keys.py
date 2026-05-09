import os
import secrets
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from pathlib import Path
from abc import ABC, abstractmethod


class InvalidKeyError(Exception):
    pass


class KeyManager:
    _KEY_LENGTH = 32
    _DEFAULT_MTIME_TOL = 24 * 60 * 60  # 24 hours | Last time modified
    _ITERATIONS = 600_000

    _DEFAULT_KEY_DIR = Path.home() / ".secret"
    _DEFAULT_KEY_FILE = _DEFAULT_KEY_DIR / "secret.key"

    def __init__(self, path: Path = None):
        self.path = path or self._DEFAULT_KEY_FILE

    @property
    def path(self) -> Path:
        return self._path

    @path.setter
    def path(self, value):
        if not isinstance(value, (Path, str)):
            raise TypeError(f"Expected Path or str, got {type(value).__name__}")


        path = Path(value) if isinstance(value, str) else value

        if path.is_dir():
            raise ValueError("Path must be a file, not a directory")

        self._path = path

    def generate_key(self, force: bool = False) -> Path:

        if self.path.exists() and not force:
            raise FileExistsError(
                f"Key `{self.path.name}` already exists at `{self.path.parent}` | Use --force to overwrite."
            )

        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)

        key = secrets.token_bytes(32)

        self.path.write_bytes(key)
        self.path.chmod(0o600)

        return self.path

    def load_key(self) -> bytes:

        if not self.path.exists():
            raise FileNotFoundError(f"Couldn't find key file: {self.path}")

        mtime = self.path.stat().st_mtime
        if (time.time() - mtime) > self._DEFAULT_MTIME_TOL:
            print(
                f"Warning: Key '{self.path.name}' is older than {self._DEFAULT_MTIME_TOL // 3600}h. Consider rotating it."
            )

        key = self.path.read_bytes()
        self.validate_key(key)
        return key

    @staticmethod
    def validate_key(key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("Key must be bytes")

        if len(key) != 32:
            raise InvalidKeyError(f"Invalid length. Expected 32, got {len(key)}")


# ───────────────────────────────────────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────────────────────────────────────
# ───────────────────────────────────────────────────────────────────────────────────────────────


class KeySource(ABC):
    @abstractmethod
    def get_key(self, existing_salt: bytes | None = None) -> bytes: ...

    @abstractmethod
    def get_salt(self) -> bytes: ...


class PasswordSource(KeySource):
    def __init__(self, password: str):
        self._salt = secrets.token_bytes(32)
        self._password = bytearray(password.encode())

    def _clear_password(self):
        # Overwrite the bytearray before clearing reference
        for i in range(len(self._password)):
            self._password[i] = 0
        self._password = bytearray()

    def derive_key(self, salt: bytes) -> bytes:
        if not self._password:
            raise RuntimeError("Password already consumed")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KeyManager._ITERATIONS,
        )
        try:
            return kdf.derive(bytes(self._password))
        finally:
            self._clear_password()

    def get_key(self, existing_salt: bytes | None = None) -> bytes:
        salt = existing_salt if existing_salt is not None else self._salt
        return self.derive_key(salt)

    def get_salt(self) -> bytes:
        return self._salt


class FileSource(KeySource):
    def __init__(self, path: Path):
        self._manager = KeyManager(path)

    def get_key(self, existing_salt: bytes | None = None) -> bytes:
        return self._manager.load_key()

    def get_salt(self) -> bytes:
        return b"\x00" * 32  # Empty salt
