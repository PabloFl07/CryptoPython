
import struct
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM , ChaCha20Poly1305

@dataclass
class FileHeader:
    # Formato: ! (Network/Big-endian) 4s (Magic) B (Alg) 32s (nonce_salt) H (NameLen) 32s ( password_salt )
    # Total: 4 + 1 + 1 + 4 + 32 + 2 = 44 bytes 
    STRUCT_FORMAT = "!5sB 32s 32s H"
    MAGIC = b"Olesa"
    
    # IDs de algoritmos
    AESGCM_ID = 1
    CHACHA20_ID = 2

    algorithm_id: int
    nonce_salt: bytes
    password_salt : bytes
    name_len: int
    
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
    def read_metadata(cls, file, key_source):
        with open(file, "rb") as f_in:
            fixed_header_data = f_in.read(cls.size())
            header = cls.unpack(fixed_header_data)
            file_name = f_in.read(header.name_len).decode("utf-8")

            key = key_source.get_key(existing_salt=header.password_salt)

            cipher = cls.read_cipher(header.algorithm_id)(key)

        return header , key , cipher, file_name
    
    @classmethod
    def read_cipher(cls, alg_id: int):
        mapping = {
            cls.AESGCM_ID: AESGCM,
            cls.CHACHA20_ID: ChaCha20Poly1305
        }
        return mapping[alg_id]
    
    @classmethod
    def size(cls):
        return struct.calcsize(cls.STRUCT_FORMAT)
