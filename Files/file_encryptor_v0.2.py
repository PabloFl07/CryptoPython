from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import secrets
from pathlib import Path
import os
import time
import hashlib
import logging
import argparse
import sys

# Configuración por defecto
DEFAULT_KEY_DIR = Path.home() / ".crypto_keys"
DEFAULT_KEY_FILE = DEFAULT_KEY_DIR / "secret.key"
DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB
TAG_SIZE = 16  # Tamaño del tag de autenticación de AES-GCM

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Chunk-based AES-GCM File Encryptor/Decryptor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s genkey                                    # Generate new key in default location
  %(prog)s --keyfile mykey.key genkey                # Generate key in specific location
  %(prog)s encrypt file.txt                          # Encrypt file.txt
  %(prog)s decrypt file.txt.enc                      # Decrypt file.txt.enc
  %(prog)s decrypt file.txt.enc --verify             # Decrypt and verify integrity
  %(prog)s decrypt file.txt.enc --verify --delete    # Decrypt, verify and delete .dec file
  %(prog)s verify original.txt decrypted.txt         # Verify integrity manually
        """
    )
    
    parser.add_argument(
        "--keyfile",
        type=str,
        default=str(DEFAULT_KEY_FILE),
        help=f"Path to the key file (default: {DEFAULT_KEY_FILE})"
    )
    
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Chunk size in bytes (default: {DEFAULT_CHUNK_SIZE})"
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        help="Path to log file (if not specified, logs only to console)"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando genkey
    genkey_parser = subparsers.add_parser(
        "genkey",
        help="Generate a new encryption key"
    )
    genkey_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key file"
    )

    # Subcomando encrypt
    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file"
    )
    encrypt_parser.add_argument(
        "file",
        help="Path to the file to encrypt"
    )
    encrypt_parser.add_argument(
        "--output",
        help="Output file path (default: input_file.enc)"
    )

    # Subcomando decrypt
    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt a file"
    )
    decrypt_parser.add_argument(
        "file",
        help="Path to the file to decrypt"
    )
    decrypt_parser.add_argument(
        "--output",
        help="Output file path (default: removes .enc extension)"
    )
    decrypt_parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify integrity after decryption (needs original file)"
    )
    decrypt_parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete .dec file after successful verification (only with --verify)"
    )

    # Subcomando verify
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify integrity of decrypted file"
    )
    verify_parser.add_argument(
        "original",
        help="Path to the original file"
    )
    verify_parser.add_argument(
        "decrypted",
        help="Path to decrypted file"
    )
    
    return parser.parse_args()


def setup_logging(log_file=None):
    """Configura el sistema de logging"""
    handlers = [logging.StreamHandler()]
    
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True
    )


def gen_key(key_path: Path, force: bool = False) -> bytes:
    """
    Genera una llave de 256 bits para AES256 y la guarda en un archivo
    con permisos seguros.

    Args:
        key_path: Ruta donde guardar la clave
        force: Si True, sobrescribe la clave existente

    Returns:
        key (bytes): La clave generada
    """
    if key_path.exists() and not force:
        logger.error(f"La clave ya existe en {key_path}")
        logger.error("Use --force para sobrescribir")
        sys.exit(1)

    key = secrets.token_bytes(32)
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    with open(key_path, "wb") as keyf:
        keyf.write(key)
    os.chmod(key_path, 0o600)

    logger.info(f"✓ Clave generada y guardada en: {key_path}")
    logger.warning("¡IMPORTANTE! Guarda esta clave de forma segura. Sin ella no podrás descifrar tus archivos.")
    
    return key


def load_key(key_path: Path) -> bytes:
    """
    Carga una clave del archivo.

    Args:
        key_path: Ruta de la clave

    Returns:
        key (bytes): La clave cargada

    Raises:
        FileNotFoundError: Si la clave no existe
    """
    if not key_path.exists():
        logger.error(f"No se encontró la clave en: {key_path}")
        logger.error("Genera una clave primero con: genkey")
        sys.exit(1)

    with open(key_path, "rb") as key_file:
        key = key_file.read()
    
    if len(key) != 32:
        logger.error("Clave inválida: debe tener 32 bytes")
        sys.exit(1)
    
    return key


def calculate_hash(file_path: Path, chunk_size: int = 1 * 1024 * 1024) -> str:
    """Calcula el hash SHA-256 de un archivo"""
    hash_obj = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def encrypt_file(key: bytes, file_path: Path, output_path: Path = None, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Path:
    """
    Cifra un archivo usando AES-GCM con chunks.

    Args:
        key: Clave de cifrado de 32 bytes
        file_path: Ruta al archivo a cifrar
        output_path: Ruta de salida (opcional)
        chunk_size: Tamaño del chunk

    Returns:
        Path: Ruta al archivo cifrado
    """
    if not file_path.exists():
        logger.error(f"Archivo no encontrado: {file_path}")
        sys.exit(1)
    
    if output_path is None:
        output_path = Path(str(file_path) + ".enc")
    
    start_time = time.time()

    try:
        base_nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        file_name = file_path.name

        with open(file_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(base_nonce)
            logger.info(f"Cifrando {file_name}...")

            chunk_number = 0
            while chunk := f_in.read(chunk_size):
                counter_bytes = chunk_number.to_bytes(12, "big")
                nonce = bytes(a ^ b for a, b in zip(base_nonce, counter_bytes))
                associated_data = f"{file_name}:{chunk_number}".encode()

                encrypted_chunk = aesgcm.encrypt(nonce, chunk, associated_data)
                f_out.write(encrypted_chunk)
                logger.debug(f"Chunk {chunk_number} cifrado ({len(chunk)} bytes)")
                chunk_number += 1

        elapsed = time.time() - start_time
        size_mb = file_path.stat().st_size / (1024 * 1024)
        logger.info(
            f"✓ Archivo cifrado en {elapsed:.2f}s ({size_mb:.1f} MB, {size_mb / elapsed:.1f} MB/s)"
        )
        logger.info(f"✓ Archivo cifrado guardado en: {output_path}")

        return output_path

    except KeyboardInterrupt:
        logger.error("\n[!] Cifrado interrumpido")
        if output_path.exists():
            output_path.unlink()
        sys.exit(1)
    except Exception as e:
        logger.error(f"[!] Error durante el cifrado: {e}")
        if output_path.exists():
            output_path.unlink()
        raise


def decrypt_file(key: bytes, encrypted_file_path: Path, output_path: Path = None, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Path:
    """
    Descifra un archivo cifrado con AES-GCM.

    Args:
        key: Clave de descifrado de 32 bytes
        encrypted_file_path: Ruta al archivo cifrado
        output_path: Ruta de salida (opcional)
        chunk_size: Tamaño del chunk

    Returns:
        Path: Ruta al archivo descifrado
    """
    if not encrypted_file_path.exists():
        logger.error(f"Archivo no encontrado: {encrypted_file_path}")
        sys.exit(1)
    
    if output_path is None:
        output_path = Path(str(encrypted_file_path).replace(".enc", ".dec"))

    try:
        file_name = encrypted_file_path.name.replace(".enc", "")
        aesgcm = AESGCM(key)

        with open(encrypted_file_path, "rb") as f_in, open(output_path, "wb") as f_out:
            base_nonce = f_in.read(12)
            if len(base_nonce) != 12:
                raise ValueError("Archivo cifrado corrupto: nonce inválido")

            chunk_number = 0
            while True:
                counter_bytes = chunk_number.to_bytes(12, "big")
                nonce = bytes(a ^ b for a, b in zip(base_nonce, counter_bytes))
                encrypted_chunk = f_in.read(chunk_size + TAG_SIZE)
                if not encrypted_chunk:
                    break

                associated_data = f"{file_name}:{chunk_number}".encode()
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, associated_data)
                f_out.write(decrypted_chunk)
                chunk_number += 1

        logger.info(f"✓ Archivo descifrado: {output_path}")
        return output_path

    except InvalidTag:
        logger.error("[!] Error: Clave incorrecta o archivo manipulado")
        if output_path.exists():
            output_path.unlink()
        sys.exit(1)
    except Exception as e:
        logger.error(f"[!] Error durante el descifrado: {e}")
        if output_path.exists():
            output_path.unlink()
        sys.exit(1)


def rename_dec_file(decrypted_path: Path, keep_copy: bool = True) -> Path:
    """
    Renombra un archivo .dec eliminando la extensión y opcionalmente mantiene una copia .dec

    Args:
        decrypted_path: Ruta al archivo .dec
        keep_copy: Si True, mantiene una copia con extensión .dec

    Returns:
        Path: Nueva ruta sin la extensión .dec
    """
    if not str(decrypted_path).endswith(".dec"):
        return decrypted_path
    
    final_path = Path(str(decrypted_path).replace(".dec", ""))
    
    if keep_copy:
        # Copiar el contenido al archivo final (sin .dec)
        import shutil
        shutil.copy2(decrypted_path, final_path)
        logger.info(f"✓ Archivo copiado a: {final_path}")
        logger.info(f"✓ Copia de respaldo mantenida en: {decrypted_path}")
    else:
        # Solo renombrar (mueve el archivo)
        decrypted_path.rename(final_path)
        logger.info(f"✓ Archivo renombrado a: {final_path}")
    
    return final_path


def verify_integrity(original_path: Path, decrypted_path: Path, delete_dec: bool = False) -> bool:
    """
    Verifica la integridad comparando hashes.

    Args:
        original_path: Ruta al archivo original
        decrypted_path: Ruta al archivo descifrado
        delete_dec: Si True, elimina el archivo .dec después de verificar

    Returns:
        bool: True si los archivos son idénticos
    """
    logger.info("Verificando integridad...")
    
    if not original_path.exists():
        logger.error(f"Archivo original no encontrado: {original_path}")
        return False
    
    if not decrypted_path.exists():
        logger.error(f"Archivo descifrado no encontrado: {decrypted_path}")
        return False
    
    original_hash = calculate_hash(original_path)
    decrypted_hash = calculate_hash(decrypted_path)

    if original_hash == decrypted_hash:
        logger.info("✓ Integridad verificada: Los archivos son idénticos")
        logger.info(f"  Hash SHA-256: {original_hash}")

        # Si se solicita eliminar el .dec, lo hacemos
        if delete_dec and str(decrypted_path).endswith(".dec"):
            try:
                decrypted_path.unlink()
                logger.info(f"✓ Archivo temporal .dec eliminado: {decrypted_path}")
            except Exception as e:
                logger.warning(f"No se pudo eliminar el archivo .dec: {e}")
        
        return True
    else:
        logger.error("✗ FALLO DE INTEGRIDAD: Los archivos difieren")
        logger.error(f"  Hash original:   {original_hash}")
        logger.error(f"  Hash descifrado: {decrypted_hash}")
        return False


def main():
    args = parse_args()
    
    # Configurar logging
    setup_logging(args.log_file)
    
    # Convertir rutas a Path objects
    key_path = Path(args.keyfile)
    
    try:
        if args.command == "genkey":
            force = getattr(args, 'force', False)
            gen_key(key_path, force=force)
        
        elif args.command == "encrypt":
            if not key_path.exists():
                logger.warning("Clave no encontrada, generando una nueva...")
                gen_key(key_path)
            key = load_key(key_path)
            file_path = Path(args.file)
            output_path = Path(args.output) if args.output else None
            encrypt_file(key, file_path, output_path, args.chunk_size)
        
        elif args.command == "decrypt":
            key = load_key(key_path)
            encrypted_path = Path(args.file)
            output_path = Path(args.output) if args.output else None
            decrypted_path = decrypt_file(key, encrypted_path, output_path, args.chunk_size)

            # Renombrar el archivo (siempre, manteniendo copia .dec)
            final_path = rename_dec_file(decrypted_path, keep_copy=True)

            # Verificación de integridad si se solicita
            if args.verify:
                original_path = Path(str(encrypted_path).replace(".enc", ""))
                if original_path.exists():
                    # Verificar integridad usando el archivo renombrado
                    delete_dec = getattr(args, 'delete', False)
                    success = verify_integrity(original_path, final_path, delete_dec=False)
                    
                    # Si se solicita --delete y la verificación fue exitosa, eliminar la copia .dec
                    if success and delete_dec:
                        try:
                            decrypted_path.unlink()
                            logger.info(f"✓ Copia de respaldo .dec eliminada: {decrypted_path}")
                        except Exception as e:
                            logger.warning(f"No se pudo eliminar la copia .dec: {e}")
                    elif not success:
                        logger.warning("La verificación falló, se mantiene la copia .dec para inspección")
                else:
                    logger.warning(f"No se encontró el archivo original para verificar: {original_path}")
                    logger.warning("Se mantiene la copia .dec")
        
        elif args.command == "verify":
            original_path = Path(args.original)
            decrypted_path = Path(args.decrypted)
            verify_integrity(original_path, decrypted_path, delete_dec=False)
    
    except KeyboardInterrupt:
        logger.error("\n[!] Operación interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        logger.error(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()