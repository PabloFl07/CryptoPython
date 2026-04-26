import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization

def calculate_file_hash(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def get_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def wipe_memory(*buffers: bytearray):
    for buffer in buffers:
        if buffer:
            for i in range(len(buffer)):
                buffer[i] = 0

def format_public_key(public_key_object) -> str:
    return public_key_object.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

def raw_public_key(public_key_object):
    public_key_object.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64_decode(data: str) -> bytes:
    return base64.b64decode(data)