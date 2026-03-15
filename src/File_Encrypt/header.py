import struct
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


@dataclass
class FileHeader:
    # Total: 5 + 1 + 32 + 32 + 2 = 72 bytes
    STRUCT_FORMAT = "!5sB32s32sH"
    MAGIC = b"Olesa"

    AESGCM_ID = 1
    CHACHA20_ID = 2

    algorithm_id: int
    nonce_salt: bytes
    password_salt: bytes | None
    name_len: int

    _CIPHER_MAP = {1: AESGCM, 2: ChaCha20Poly1305}

    def pack(self) -> bytes:

        return struct.pack(
            self.STRUCT_FORMAT,
            self.MAGIC,
            self.algorithm_id,
            self.nonce_salt,
            self.password_salt,
            self.name_len,
        )

    @classmethod
    def unpack(cls, data: bytes):
        unpacked = struct.unpack(cls.STRUCT_FORMAT, data)
        if unpacked[0] != cls.MAGIC:
            raise ValueError("Unrecognized or corrupt file (Magic Number mismatch)")

        return cls(
            algorithm_id=unpacked[1],
            nonce_salt=unpacked[2],
            password_salt=unpacked[3],
            name_len=unpacked[4],
        )

    @classmethod
    def read_cipher(cls, algorithm_id: int):
        return cls._CIPHER_MAP[algorithm_id]

    @classmethod
    def size(cls) -> int:
        return struct.calcsize(cls.STRUCT_FORMAT)
