from pathlib import Path
import hashlib


class Integrity:

    def __init__(self, original_path : Path , decrypted_path : Path, algorithm : str = "sha256"):
        self.original_path = original_path
        self.decrypted_path = decrypted_path
        self.algorithm = algorithm.lower().replace("-", "")



    @staticmethod
    def hash_file(file_path: Path, algorithm: str = "sha256") -> str:
        try:
            with open(file_path, "rb") as file:
                digest = hashlib.file_digest(file, algorithm)
            return digest.hexdigest()

        except ValueError:
            raise ValueError(f"Algoritmo de hash no soportado: {algorithm}")
        

    def verify_integrity(self) -> bool:
        if not self.original_path.exists() or not self.decrypted_path.exists():
            return False

        if (
            self.original_path.stat().st_size
            != self.decrypted_path.stat().st_size
        ):
            return False

        original_hash = self.hash_file(self.original_path, self.algorithm)
        decrypted_hash = self.hash_file(self.decrypted_path, self.algorithm)


        print(original_hash)
        print(decrypted_hash)

        if original_hash == decrypted_hash:
            return True
        else:
            return False
    
        




"""
    def verify_integrity(self) -> bool:
        # Validar que ambos archivos existen
        if not self.original_file_path.exists() or self.decrypted_file_path.exists():
            return False

        # Compara el tamaño de los archivos para descartar directamente
        if (
            self.original_file_path.stat().st_size
            != self.decrypted_file_path.stat().st_size
        ):
            return False

        # Calcular hashes SHA-256 de ambos archivos
        original_hash = self.calculate_hash(self.original_file_path, self.algorithm)
        decrypted_hash = self.calculate_hash(self.decrypted_file_path, self.algorithm)

        # Comparar hashes
        if original_hash == decrypted_hash:
            return True
        else:
            # Los hashes no coinciden: los archivos difieren
            return False

"""