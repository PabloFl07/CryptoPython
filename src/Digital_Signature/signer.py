import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _public_key(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_file(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Envelope(ABC):
    def __init__(self, signature: bytes, pubkey: str, timestamp: str):
        self.signature = signature      
        self.pubkey    = pubkey
        self.timestamp = timestamp

    @property
    def sig_b64(self):
        return base64.b64encode(self.signature).decode()

    @abstractmethod
    def to_dict(self) -> dict: ... 


class Detached(Envelope):
    def __init__(self, filename: str, sha256: str, signature: bytes, pubkey: str, timestamp: str):
        super().__init__(signature, pubkey, timestamp)
        self.filename = filename
        self.sha256   = sha256

    def to_dict(self) -> dict:
        return {
            "mode":       "detached",
            "filename":   self.filename,
            "sha256":     self.sha256,
            "signature":  self.sig_b64,
            "public_key": self.pubkey,
            "timestamp":  self.timestamp,
        }

class Inline(Envelope):
    """
    Envelope format:
        {
        "mode":      "inline",
        "filename":  "<original name>",
        "data":      "<base64-encoded file content>",
        "signature":       "<base64 Ed25519 signature over the raw file bytes>",
        "public_key":    "<PEM public key>",
        "timestamp": "<ISO-8601 UTC>"
        }
    """
    def __init__(self, filename: str, data: bytes, sig: bytes, pubkey: str, timestamp: str):
        super().__init__(sig, pubkey, timestamp)
        self.filename = filename
        self.data     = data       

    def to_dict(self) -> dict:

        return {
            "mode":       "inline",
            "filename":   self.filename,
            "data":       base64.b64encode(self.data).decode(),
            "signature":  self.sig_b64,
            "public_key": self.pubkey,
            "timestamp":  self.timestamp,
        }
    
class Clearsign(Envelope):
    def __init__(self, content: str, signature: bytes, pubkey, timestamp: str):
        super().__init__(signature, pubkey, timestamp)
        self.content = content

    def to_dict(self):
        return super().to_dict()

    def to_text(self) -> str:   # to_dict no aplica aquí, mejor to_text
        return (
            "-----BEGIN SIGNED TEXT-----\n"
            f"{self.content}\n"
            "-----BEGIN ED25519 SIGNATURE-----\n"
            f"{self.sig_b64}\n"
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
    def __init__(self, files: list[dict], signature: bytes, pubkey: str, timestamp: str):
        super().__init__(signature, pubkey, timestamp)
        self.files = files

    def to_dict(self) -> dict:
        return {
            "mode":       "manifest",
            "files":      self.files,
            "signature":  self.sig_b64,
            "public_key": self.pubkey,
            "timestamp":  self.timestamp,
        }

class Signer():    
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

    # ------------------------------------------------------------------ #
    # Mode 1 — Detached                                                   #
    # ------------------------------------------------------------------ #

    def sign_detached(self, input_path: Path, output_path: Path = None) -> Path:
        """
        Sign a file and write the signature to a separate .sig file.
        The original file is never modified.
        """

        if input_path.stat().st_size > self._MAX_FILE_SIZE:
            raise ValueError(f"File too large for Ed25519 full-message signing. Max: {self._MAX_FILE_SIZE / (1024 * 1024):.0f} MB")

        data = input_path.read_bytes()
        signature_bytes = self._key.sign(data)
        digest_hex = hashlib.sha256(data).hexdigest()

        output_path = output_path or input_path.with_suffix(".sig.json")

        try:
            file_descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise FileExistsError(f"Output file already exists: {output_path}. Remove it or specify a different path with --output.")

        envelope = Detached(input_path.name, digest_hex, signature_bytes, _public_key(self._key), _now_iso())

        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as output_file:
                output_file.write(json.dumps(envelope.to_dict(), indent=2))
        except Exception:
            os.unlink(output_path)
            raise
        
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
            raise ValueError(f"File too large for Ed25519 full-message signing. Max: {self._MAX_FILE_SIZE / (1024 * 1024):.0f} MB")

        data = input_path.read_bytes()
        signature_bytes = self._key.sign(data)

        output_path = output_path or input_path.with_suffix(".jsig")

        envelope = Inline(input_path.name, data, signature_bytes, _public_key(self._key), _now_iso())

        try:
            file_descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise FileExistsError(f"Output file already exists: {output_path}. Remove it or specify a different path with --output.")

        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as output_file:
                output_file.write(json.dumps(envelope.to_dict(), indent=2))
        except Exception:
            os.unlink(output_path)
            raise
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
       
        envelope = Clearsign(content, signature, "",  _now_iso())

        try:
            file_descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise FileExistsError(f"Output file already exists: {output_path}. Remove it or specify a different path with --output.")

        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as output_file:
                output_file.write(envelope.to_text())
        except Exception:
            os.unlink(output_path)
            raise
        return output_path


    # ------------------------------------------------------------------ #
    # Mode 3 — Manifest                                                   #
    # ------------------------------------------------------------------ #

    def sign_manifest(self, input_paths: list[Path], output_path: Path = None) -> Path:
        """
        Hash every file with SHA-256, sign the canonical manifest bytes,
        and write a manifest JSON.

        canonical_bytes = the UTF-8 encoding of the JSON array of
        { "path": ..., "sha256": ... } entries, sorted by path, with no
        extra whitespace — this is what gets signed so verification is
        deterministic regardless of JSON serialiser.
        """
        if not input_paths:
            raise ValueError("File list is empty")

        entries = []
        for file_path in input_paths:
            file_path = Path(file_path)
            if not file_path.is_file():
                raise FileNotFoundError(f"File not found: {file_path}")
            relative_path = file_path.relative_to(input_paths[0].parent)
            entries.append({"path": str(relative_path), "sha256": _hash_file(file_path)})

        # Sort by path so the signed payload is deterministic
        entries.sort(key=lambda e: e["path"])

        canonical_bytes = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode("utf-8")
        sig_bytes = self._key.sign(canonical_bytes)

        output_path = output_path or Path("manifest.json")

        envelope = Manifest(entries, sig_bytes, _public_key(self._key), _now_iso())

        try:
            file_descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise FileExistsError(f"Output file already exists: {output_path}. Remove it or specify a different path with --output.")

        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as output_file:
                output_file.write(json.dumps(envelope.to_dict(), indent=2))
        except Exception:
            os.unlink(output_path)
            raise

        return output_path
