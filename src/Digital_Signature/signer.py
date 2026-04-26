import json
import os
from pathlib import Path
from abc import ABC, abstractmethod
import utils

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class Envelope(ABC):
    def __init__(self, signature: bytes, private_key: Ed25519PrivateKey):
        self.signature = utils.b64_encode(signature)
        self.pubkey = utils.format_public_key(private_key.public_key())
        self.timestamp = utils.get_now_iso()

    @abstractmethod
    def to_dict(self) -> dict: ...


class Detached(Envelope):
    def __init__(
        self,
        filename: str,
        sha256: str,
        signature: bytes,
        private_key: Ed25519PrivateKey,
    ):
        super().__init__(signature, private_key)
        self.filename = filename
        self.sha256 = sha256

    def to_dict(self) -> dict:
        return {
            "mode": "detached",
            "filename": self.filename,
            "sha256": self.sha256,
            "signature": self.signature,
            "public_key": self.pubkey,
            "timestamp": self.timestamp,
        }


class Inline(Envelope):
    """ """

    def __init__(
        self,
        filename: str,
        data: bytes,
        signature: bytes,
        private_key: Ed25519PrivateKey,
    ):
        super().__init__(signature, private_key)
        self.filename = filename
        self.data = data

    def to_dict(self) -> dict:
        return {
            "mode": "inline",
            "filename": self.filename,
            "data": utils.b64_encode(self.data),
            "signature": self.signature,
            "public_key": self.pubkey,
            "timestamp": self.timestamp,
        }


class Clearsign(Envelope):
    def __init__(self, content: str, signature: bytes, private_key: Ed25519PrivateKey):
        super().__init__(signature, private_key)
        self.content = content

        _raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.pubkey_raw = utils.b64_encode(_raw)


    def to_dict(self):
        return super().to_dict()

    def to_text(self) -> str:  # to_dict no aplica aquí, mejor to_text
        return (
            "-----BEGIN SIGNED TEXT-----\n"
            f"{self.content}\n"
            "-----BEGIN ED25519 SIGNATURE-----\n"
            f"Signature: {self.signature}\n"
            f"Public key: {self.pubkey_raw}\n"
            f"Timestamp: {self.timestamp}\n"
            "-----END ED25519 SIGNATURE-----\n"
        )


class Manifest(Envelope):
    """
    Manifest format:
        {
        "mode":      "manifest",
        "files": [
          { "path": "<relative or absolute path>", "sha256": "<hex>" },
          ...
        ],
        "signature":       "<base64 Ed25519 signature over canonical_bytes>",
        "public_key":    "<PEM public key>",
        "timestamp": "<ISO-8601 UTC>"
          }
    """

    def __init__(
        self, files: list[dict], signature: bytes, private_key: Ed25519PrivateKey
    ):
        super().__init__(signature, private_key)
        self.files = files

    def to_dict(self) -> dict:
        return {
            "mode": "manifest",
            "files": self.files,
            "signature": self.signature,
            "public_key": self.pubkey,
            "timestamp": self.timestamp,
        }


class Signer:
    """
    Signs files using an Ed25519 private key.

    Three modes:
      - detached  : writes a .sig file next to the original (original untouched)
      - inline    : writes a self-contained JSON envelope  { data, sig, pubkey, ... }
      - manifest  : signs a SHA-256 hash-list of N files   { files[], sig, pubkey, ... }
    """

    _MAX_FILE_SIZE = 500 * 1024 * 1024

    def __init__(self, private_key: Ed25519PrivateKey):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("Expected an Ed25519PrivateKey instance")
        self._key = private_key

    @staticmethod
    def _write_file(path: Path, content: str) -> Path:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            os.unlink(path)
            raise
        return path

    @staticmethod
    def to_file(path: Path, envelope: Envelope) -> Path:
        """Serialize an Envelope to indented JSON and write it to a new file."""
        return Signer._write_file(path, json.dumps(envelope.to_dict(), indent=2))

    # ------------------------------------------------------------------ #
    # Mode 1 — Detached                                                   #
    # ------------------------------------------------------------------ #

    def sign_detached(self, input_path: Path, output_path: Path = None) -> Path:
        """
        Sign a file and write the signature to a separate .sig file.
        The original file is never modified.
        """

        if input_path.stat().st_size > self._MAX_FILE_SIZE:
            raise ValueError(
                f"File too large for Ed25519 full-message signing. Max: {self._MAX_FILE_SIZE / (1024 * 1024):.0f} MB"
            )

        data = input_path.read_bytes()
        signature = self._key.sign(data)

        output_path = output_path or input_path.with_suffix(".sig.json")

        envelope = Detached(
            input_path.name, utils.calculate_file_hash(input_path), signature, self._key
        )

        try:
            Signer.to_file(output_path, envelope)

        except FileExistsError:
            raise FileExistsError(
                f"Output file already exists: {output_path}. Remove it or specify a different path with --output."
            )

        return output_path

    # ------------------------------------------------------------------ #
    # Mode 2 — Inline / Envelope                                          #
    # ------------------------------------------------------------------ #

    def sign_inline(self, input_path: Path, output_path: Path = None) -> Path:
        """
        Embed the file content + signature in a single self-contained JSON.

        The signature is over the raw file bytes (before base64 encoding).
        """

        if input_path.stat().st_size > self._MAX_FILE_SIZE:
            raise ValueError(
                f"File too large for Ed25519 full-message signing. Max: {self._MAX_FILE_SIZE / (1024 * 1024):.0f} MB"
            )

        data = input_path.read_bytes()
        signature = self._key.sign(data)

        output_path = output_path or input_path.with_suffix(".jsig")
        envelope = Inline(input_path.name, data, signature, private_key=self._key)

        try:
            Signer.to_file(output_path, envelope)
        except FileExistsError:
            raise FileExistsError(
                f"Output file already exists: {output_path}. "
                "Remove it or specify a different path with --output."
            )

        return output_path

    # ------------------------------------------------------------------ #
    # Mode 4 — Clearsign (Texto Plano)                                   #
    # ------------------------------------------------------------------ #

    def sign_clearsign(self, input_path: Path, output_path: Path = None) -> Path:

        try:
            content = input_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise ValueError("Clearsign mode requires a valid UTF-8 text file")

        data = content.encode("utf-8")
        signature = self._key.sign(data)

        output_path = output_path or input_path.with_suffix(".signed.txt")
        envelope = Clearsign(content, signature, private_key=self._key)

        try:
            Signer._write_file(output_path, envelope.to_text())
        except FileExistsError:
            raise FileExistsError(
                f"Output file already exists: {output_path}. "
                "Remove it or specify a different path with --output."
            )
        return output_path

    # ------------------------------------------------------------------ #
    # Mode 3 — Manifest                                                   #
    # ------------------------------------------------------------------ #

    def sign_manifest(
        self, base_dir: Path, output_path: Path = None, recursive: bool = None
    ) -> Path:
        """
        Hash every file with SHA-256, sign the canonical manifest bytes,
        and write a manifest JSON.

        canonical_bytes = the UTF-8 encoding of the JSON array of
        { "path": ..., "sha256": ... } entries, sorted by path, with no
        extra whitespace — this is what gets signed so verification is
        deterministic regardless of JSON serialiser.
        """
        pattern = "**/*" if recursive else "*"
        files = sorted(f for f in base_dir.glob(pattern) if f.is_file())

        if not files:
            raise ValueError("File list is empty")

        entries = [
            {"path": str(f.relative_to(base_dir)), "sha256": utils.calculate_file_hash(f)}
            for f in files
        ]
        # Already sorted by glob+sorted above, but make it explicit for clarity.
        entries.sort(key=lambda e: e["path"])

        canonical_bytes = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature       = self._key.sign(canonical_bytes)

        output_path = output_path or Path("manifest.json")
        envelope    = Manifest(entries, signature, private_key=self._key)

        try:
            Signer.to_file(output_path, envelope)
        except FileExistsError:
            raise FileExistsError(
                f"Output file already exists: {output_path}. "
                "Remove it or specify a different path with --output."
            )

        return output_path
