from integrity import Integrity
from keys import KeySource
from pathlib import Path
from engine import CipherEngine
from header import FileHeader
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM


class Run:
    # Aux function to translate from an empty argument input ( -a / -c ) to a flag
    @staticmethod
    def get_cipher(args) -> str:

        CIPHER_DISPATCH = {
            "a": (AESGCM, 1),
            "c": (ChaCha20Poly1305, 2),
        }

        for flag, cipher in CIPHER_DISPATCH.items():
            if getattr(args, flag[0], False):
                return cipher
        return CIPHER_DISPATCH.get("a")  # Default | AESGCM

    @staticmethod
    def encrypt(
        in_file: Path,
        out_file: Path,
        key_source: KeySource,
        cipher: str,
    ):
        salt = key_source.get_salt()  # Into the File Header
        key = key_source.get_key()

        cipher, cipher_id = cipher

        engine = CipherEngine(key, cipher(key), cipher_id)

        engine.encrypt_file(in_file, out_file, salt)

    @staticmethod
    def decrypt(input_path: Path, output_path: Path, key_source: KeySource):

        header, key, cipher, name = FileHeader.read_metadata(input_path, key_source)

        engine = CipherEngine(key, cipher(key), header.algorithm_id)

        engine.decrypt_file(input_path, output_path, header.nonce_salt, name)

    @staticmethod
    def verify(original, decrypted, algorithm):
        integrity = Integrity(original, decrypted, algorithm)
        return integrity.verify_integrity()

    @staticmethod
    def hash(file, algorithm):
        return f"{algorithm.lower().replace('-', '')} Hash: {Integrity.hash_file(file, algorithm)}"