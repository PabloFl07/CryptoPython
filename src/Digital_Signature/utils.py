import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


#  ────────────────────────────────────────────────────

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64_decode(data: str) -> bytes:
    return base64.b64decode(data)

def calculate_file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def get_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


#  ────────────────────────────────────────────────────

def wipe_memory(*buffers: bytearray):
    for buffer in buffers:
        if buffer:
            for i in range(len(buffer)):
                buffer[i] = 0

def key_fingerprint(pubkey: Ed25519PublicKey) -> str:
    raw = pubkey.public_bytes(
        encoding=serialization.Encoding.Raw, 
        format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]

#  ────────────────────────────────────────────────────

def format_public_key(public_key_object) -> str:
    return public_key_object.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

def raw_public_key(public_key_object):
    return public_key_object.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

def load_raw_public_key(raw_public_key):
    return Ed25519PublicKey.from_public_bytes(b64_decode(raw_public_key))

def load_pem_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f" {type(key).__name__}") # ! Error message
    return key

