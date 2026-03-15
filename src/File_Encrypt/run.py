from integrity import verify_integrity, hash_file
from keys import KeySource
from pathlib import Path
from engine import CipherEngine
from header import FileHeader


class Run:
    @staticmethod
    def encrypt(
        input_path: Path,
        output_path: Path,
        key_source: KeySource,
        cipher: str,
    ):
        salt = key_source.get_salt()  # Into the File Header
        key = key_source.get_key()

        cipher_cls, cipher_id = cipher

        engine = CipherEngine(key, cipher_cls(key), cipher_id)

        engine.encrypt_file(input_path, output_path, salt)

    @staticmethod
    def decrypt(input_path: Path, output_path: Path, key_source: KeySource):

        try:
            with open(input_path, "rb") as input_file:
                fixed_header_data = input_file.read(FileHeader.size())
                header = FileHeader.unpack(fixed_header_data)

                file_name = Path(input_file.read(header.name_len).decode("utf-8")).name

        except FileNotFoundError:
            raise FileNotFoundError("File to decrypt not found")

        key = key_source.get_key(existing_salt=header.password_salt)
        cipher = FileHeader.read_cipher(header.algorithm_id)
        engine = CipherEngine(key, cipher(key), header.algorithm_id)

        engine.decrypt_file(input_path, output_path, header.nonce_salt, file_name)

    @staticmethod
    def verify(original, decrypted, algorithm):
        return verify_integrity(original, decrypted, algorithm)

    @staticmethod
    def hash(file, algorithm):
        return (
            f"{algorithm.lower().replace('-', '')} Hash: {hash_file(file, algorithm)}"
        )
