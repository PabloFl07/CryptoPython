from pathlib import Path
import hashlib


def hash_file(file_path: Path, algorithm: str = "sha256") -> str:
    try:
        with open(file_path, "rb") as file:
            digest = hashlib.file_digest(file, algorithm)
        return digest.hexdigest()
    except ValueError:
        raise ValueError(f"Algorithm not supported: {algorithm}")


def verify_integrity(
    original_path: Path, decrypted_path: Path, algorithm: str = "sha256"
) -> bool:
    if not original_path.exists() or not decrypted_path.exists():
        return False

    if original_path.stat().st_size != decrypted_path.stat().st_size:
        return False

    original_hash = hash_file(original_path, algorithm)
    decrypted_hash = hash_file(decrypted_path, algorithm)

    return original_hash == decrypted_hash
