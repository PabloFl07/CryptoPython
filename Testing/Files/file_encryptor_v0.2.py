from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import secrets
from pathlib import Path
import os
import time
import hashlib
import logging


# Configuración de rutas
test_path = Path.home() / "Dev" / "CryptoPython" / "Sandbox"/ ".secret" / "secret.key"
file_path = "/home/pablo/Dev/CryptoPython/Sandbox/hola.txt"

# Tamaños de chunk
DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB
CHUNK_SIZE = DEFAULT_CHUNK_SIZE
TAG_SIZE = 16  # Tamaño del tag de autenticación de AES-GCM


log_path = Path.home() / "Dev" / "CryptoPython" / "Sandbox" / "crypto.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_path, encoding='utf-8'),
        logging.StreamHandler()  # También a consola
    ]
)

logger = logging.getLogger(__name__)



def gen_key() -> bytes:
    """
    Genera una llave de 256 bits para AES256 y la guarda en un archivo
    con permisos seguros
    
    Returns:
        key (bytes): La clave generada
    """
    key = secrets.token_bytes(32)
    key_path = test_path
    key_path.parent.mkdir(exist_ok=True, mode=0o700)
    
    with open(key_path, 'wb') as keyf:
        keyf.write(key)
    os.chmod(key_path, 0o600)
    
    return key


def load_key() -> bytes:
    """
    Carga una clave del archivo, si no existe, crea una clave nueva
    
    Returns:
        key (bytes): La clave cargada o generada
    """
    key_path = test_path
    if not key_path.exists():
        print("No se ha encontrado la clave, generando una nueva...")
        return gen_key()
    
    with open(key_path, 'rb') as keyf:
        return keyf.read()


def calculate_hash(file_name, chunk_size=1*1024*1024):
    """Calcula el hash SHA-256 de un archivo"""
    hash_obj = hashlib.sha256()
    with open(file_name, "rb") as f:
        while chunk := f.read(chunk_size):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def encrypt(key, nonce, data, aad):
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data, aad)

def decrypt(key,nonce, data, aad):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, aad)


def encrypt_file(key, file_path):
    """
    Cifra un archivo usando AES-GCM con chunks
    
    Args:
        key: Clave de cifrado de 32 bytes
        file_path: Ruta al archivo a cifrar
        
    Returns:
        str: Ruta al archivo cifrado
    """
    encrypted_file_path = file_path + ".enc"
    start_time = time.time()
    
    try:
        # Generar UN nonce único para todo el archivo
        nonce = secrets.token_bytes(12)
        file_name = os.path.basename(file_path)
        
        with open(file_path, "rb") as f_in, open(encrypted_file_path, "wb") as f_out:
            # Escribir el nonce UNA SOLA VEZ al inicio del archivo
            f_out.write(nonce)
            logger.info("Cifrando %s...", file_name)
            
            # Cifrar el archivo por chunks
            chunk_number = 0
            while chunk := f_in.read(CHUNK_SIZE):
                # Usar el número de chunk como parte de los datos asociados
                # para vincular cada chunk a su posición
                associated_data = f"{file_name}:{chunk_number}".encode()
                
                # Cifrar el chunk (incluye el tag de autenticación de 16 bytes)
                encrypted_chunk = encrypt(key, nonce, chunk, associated_data)
                f_out.write(encrypted_chunk)
                logger.debug("Chunk %d cifrado (%d bytes)", chunk_number, len(chunk))
                chunk_number += 1
        
        # Estadísticas

        elapsed = time.time() - start_time
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        encryption_speed = file_size_mb / elapsed_time if elapsed_time > 0 else 0

        logger.info("✓ Archivo cifrado en %.2fs (%.1f MB, %.1f MB/s)",
                    elapsed, size_mb, size_mb / elapsed)
        

        
        return encrypted_file_path
        
    except KeyboardInterrupt:
        print("\n[!] Cifrado interrumpido")
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
        raise
    except Exception as e:
        print(f"[!] Error durante el cifrado: {e}")
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
        raise


def decrypt_file(key, encrypted_file_path):
    """
    Descifra un archivo cifrado con AES-GCM
    
    Args:
        key: Clave de descifrado de 32 bytes
        encrypted_file_path: Ruta al archivo cifrado
        
    Returns:
        str: Ruta al archivo descifrado o None si falla
    """
    decrypted_file_path = encrypted_file_path.replace(".enc", ".dec")
    
    try:
        # Extraer el nombre del archivo original desde el path cifrado
        file_name = os.path.basename(encrypted_file_path.replace(".enc", ""))
        
        with open(encrypted_file_path, "rb") as f_in, open(decrypted_file_path, "wb") as f_out:
            # Leer el nonce UNA SOLA VEZ del inicio del archivo
            nonce = f_in.read(12)
            if len(nonce) != 12:
                raise ValueError("Archivo cifrado corrupto: nonce inválido")
            
            # Descifrar el archivo por chunks
            chunk_number = 0
            while True:
                # Leer chunk cifrado (datos + tag de 16 bytes)
                encrypted_chunk = f_in.read(CHUNK_SIZE + TAG_SIZE)
                if not encrypted_chunk:
                    break
                
                # Usar los mismos datos asociados que en el cifrado
                associated_data = f"{file_name}:{chunk_number}".encode()
                
                # Descifrar el chunk
                decrypted_chunk = decrypt(key,nonce, encrypted_chunk, associated_data)
                f_out.write(decrypted_chunk)
                chunk_number += 1
        
        print(f"✓ Archivo descifrado: {decrypted_file_path}")
        return decrypted_file_path
        
    except InvalidTag:
        print("[!] Error: Clave incorrecta o archivo manipulado")
        if os.path.exists(decrypted_file_path):
            os.remove(decrypted_file_path)
        return None
    except Exception as e:
        print(f"[!] Error durante el descifrado: {e}")
        if os.path.exists(decrypted_file_path):
            os.remove(decrypted_file_path)
        return None


def verify_integrity(original_path, decrypted_path):
    """
    Verifica la integridad comparando hashes y renombra el archivo descifrado
    
    Args:
        original_path: Ruta al archivo original
        decrypted_path: Ruta al archivo descifrado
    """
    print("\nVerificando integridad...")
    original_hash = calculate_hash(original_path)
    decrypted_hash = calculate_hash(decrypted_path)
    
    print(f"  Hash original:   {original_hash}")
    print(f"  Hash descifrado: {decrypted_hash}")
    
    if original_hash == decrypted_hash:
        print("✓ Integridad verificada: Los archivos son idénticos")
        
        # Renombrar el archivo descifrado (quitar extensión .dec)
        final_path = decrypted_path.replace(".dec", "")
        os.rename(decrypted_path, final_path)
        print(f"✓ Archivo renombrado a: {final_path}")
    else:
        print("✗ FALLO DE INTEGRIDAD: Los archivos difieren")


# Ejemplo de uso
if __name__ == "__main__":
    # Cargar o generar clave
    key = load_key()
    
    # Ejemplo 1: Cifrar archivo
    print("=== CIFRADO ===")
    encrypted_path = encrypt_file(key, file_path)
    
    # Ejemplo 2: Descifrar archivo
    print("\n=== DESCIFRADO ===")
    decrypted_path = decrypt_file(key, encrypted_path)
    
    # Ejemplo 3: Verificar integridad
    if decrypted_path:
        verify_integrity(file_path, decrypted_path)