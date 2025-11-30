"""
Encriptador/Desencriptador de archivos usando AES-GCM con procesamiento por chunks.

Este script proporciona funcionalidades para:
- Generar claves de cifrado seguras
- Cifrar archivos de cualquier tamaño usando chunks
- Descifrar archivos cifrados
- Verificar la integridad de los archivos descifrados

Características de seguridad:
- AES-256-GCM (Galois/Counter Mode) para cifrado autenticado
- Nonces únicos derivados para cada chunk
- Datos asociados (AAD) para vincular chunks con su posición
- Protección contra manipulación mediante tags de autenticación

!! ATENCION !! Este programa no implementa protocolos estándar de criptografía y no ha sido evaluado como tal.
"""
# TODO Encriptar carpetas: comprimir carpeta , encriptar comprimido.
# TODO Funcion "log" para loggear con un formato a archivo y con otro a consola ( formatos listos , solo integrar )

# ChangeLog
# * Derivación de nonces por BLAKE2s PRF
# * Escribir y leer metadatos en los archivos encriptados para evitar conflictos con los parámetros.

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from tqdm import tqdm
from pathlib import Path
import secrets
import os
import time
import hashlib
import logging
import argparse
import sys
import datetime

# ============================================================================
# CONFIGURACIONES POR DEFECTO
# ============================================================================

# Directorio donde se guarda la clave por defecto
DEFAULT_KEY_DIR = Path.home() / ".secret"
DEFAULT_KEY_FILE = DEFAULT_KEY_DIR / "secret.key"

# Tamaño de chunk para procesar archivos grandes (2 MB)
# Los archivos se dividen en chunks para evitar cargar todo en memoria
DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB


# Encabezado del archivo encriptado
MAGIC = b"ACG1"  # 4 bytes
FLAGS = 0x00
CHUNK_SIZE_LEN = 4

SALT_LEN = 32
TAG_SIZE = 16  # Tamaño del tag de autenticación de AES-GCM (16 bytes)

# Cantidad de segundos de diferencia entre la fecha actual y la última fecha de modificación de la llave que toleramos para considerarla "segura"
# Se le suma a la última fecha de modificación para comprobarla con la fecha actual
KEY_MTIME_TOL = 4 * 3600


# ============================================================================
# CONFIGURACIÓN DE ARGUMENTOS
# ============================================================================


def parse_args():
    """
    Configura y parsea los argumentos de línea de comandos.

    El script tiene 4 comandos principales:
    - genkey: Genera una nueva clave de cifrado
    - encrypt: Cifra un archivo
    - decrypt: Descifra un archivo
    - verify: Verifica la integridad de un archivo descifrado

    Returns:
        argparse.Namespace: Argumentos parseados
    """
    parser = argparse.ArgumentParser(
        description="Chunk-based AES-GCM File Encryptor/Decryptor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s genkey                                    # Generar nueva clave en ubicación por defecto
  %(prog)s --keyfile mykey.key genkey                # Generar clave en ubicación específica
  %(prog)s encrypt file.txt                          # Cifrar file.txt
  %(prog)s --keyfile mykey.key encrypt file.txt      # Cifrar usando una clave específica
  %(prog)s decrypt file.txt.enc                      # Descifrar file.txt.enc
  %(prog)s decrypt file.txt.enc --verify             # Descifrar y verificar integridad
  %(prog)s decrypt file.txt.enc --verify --delete    # Descifrar, verificar y eliminar archivo .dec
  %(prog)s verify original.txt decrypted.txt         # Verificar integridad manualmente
        """,
    )

    # Argumentos globales (aplicables a todos los subcomandos)
    parser.add_argument(
        "--keyfile",
        type=str,
        default=str(DEFAULT_KEY_FILE),
        help=f"Ruta al archivo de clave (default: {DEFAULT_KEY_FILE})",
    )

    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Tamaño del chunk en bytes (default: {DEFAULT_CHUNK_SIZE})",
    )

    parser.add_argument(
        "--log-file",
        type=str,
        help="Ruta al archivo de log (si no se especifica, solo sale por consola)",
    )

    # Subcomandos
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---- Subcomando: genkey ----
    genkey_parser = subparsers.add_parser(
        "genkey", help="Generar una nueva clave de cifrado"
    )
    genkey_parser.add_argument(
        "--force", action="store_true", help="Sobrescribir archivo de clave existente"
    )

    # ---- Subcomando: encrypt ----
    encrypt_parser = subparsers.add_parser("encrypt", help="Cifrar un archivo")
    encrypt_parser.add_argument("file", help="Ruta al archivo a cifrar")
    encrypt_parser.add_argument(
        "--output", help="Ruta del archivo de salida (default: input_file.enc)"
    )

    # ---- Subcomando: decrypt ----
    decrypt_parser = subparsers.add_parser("decrypt", help="Descifrar un archivo")
    decrypt_parser.add_argument("file", help="Ruta al archivo a descifrar")
    decrypt_parser.add_argument(
        "--output", help="Ruta del archivo de salida (default: quita extensión .enc)"
    )
    decrypt_parser.add_argument(
        "--verify",
        action="store_true",
        help="Verificar integridad después del descifrado (necesita archivo original)",
    )
    decrypt_parser.add_argument(
        "--delete",
        action="store_true",
        help="Eliminar archivo .dec después de verificación exitosa (solo con --verify)",
    )

    # ---- Subcomando: verify ----
    verify_parser = subparsers.add_parser(
        "verify", help="Verificar integridad de archivo descifrado"
    )
    verify_parser.add_argument("original", help="Ruta al archivo original")
    verify_parser.add_argument("decrypted", help="Ruta al archivo descifrado")

    # ---- Subcomando: listkeys ----
    list_parser = subparsers.add_parser(
        "listkeys", help="Lista las llaves en una dirección"
    )
    list_parser.add_argument(
        "path",
        nargs="?",
        default=DEFAULT_KEY_DIR,
        help="Ruta al directorio que contiene las llaves",
    )

    return parser.parse_args()


# ============================================================================
# CONFIGURACIÓN DE LOGGING
# ============================================================================

# Loggers globales
logger = logging.getLogger("general")
logger.setLevel(logging.INFO)

file_logger = logging.getLogger("solo_archivo")
file_logger.setLevel(logging.INFO)


def setup_logging(log_file=None):
    """Configura logging para consola y opcionalmente para archivo."""

    # Limpiar handlers previos
    logger.handlers.clear()
    file_logger.handlers.clear()

    # Formato común
    file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    formatter = logging.Formatter("[%(levelname)s] %(message)s")

    # Handler de consola
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)

    # Handler de archivo (opcional)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file = logging.FileHandler(log_file, encoding="utf-8")
        file.setFormatter(file_formatter)
        logger.addHandler(file)
        file_logger.addHandler(file)


def log(level : str,  message: str, file=False):
    """
    Permite loggear un mensaje en consola y archivo con dos formatos distintos simultáneamente.

    Args:
        level (str): Soportados info , warning , error

    """
    match level:
        case "info":
            if file:
                file_logger.info(message)
            else:
                file_logger.info(message)
                logger.info(message)
        case "warning":
            if file:
                file_logger.warning(message)
            else:
                file_logger.warning(message)
                logger.warning(message)
        case "error":
            if file:
                file_logger.error(message)
            else:
                file_logger.error(message)
                logger.error(message)


def return_status(start, file_path):
    return time.time() - start, file_path.stat().st_size / (1024 * 1024)


# ============================================================================
# MANEJO DE LAS LLAVES
# ============================================================================


def gen_key(key_path: Path, force: bool = False) -> bytes:
    """
    Genera una clave de 256 bits (32 bytes) para AES-256 y la guarda
    en un archivo con permisos seguros.

    Args:
        key_path (Path): Ruta donde guardar la clave
        force (bool): Si True, sobrescribe la clave existente

    Returns:
        bytes: La clave generada (32 bytes)

    Raises:
        SystemExit: Si la clave ya existe y force=False
    """
    # Verificar si la clave ya existe
    if key_path.exists() and not force:
        log("error", f"La clave ya existe en {key_path}")
        log("error", "Use --force para sobrescribir")
        sys.exit(1)

    # Generar 32 bytes aleatorios criptográficamente seguros
    key = secrets.token_bytes(32)

    # Crear directorio con permisos seguros (solo usuario: rwx------)
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Guardar la clave en el archivo
    with open(key_path, "wb") as keyf:
        keyf.write(key)

    # Establecer permisos del archivo (solo usuario: rw-------)
    os.chmod(key_path, 0o600)

    log("info", f"✓ Clave generada y guardada en: {key_path}")

    return key


def load_key(key_path: Path) -> bytes:
    """
    Carga una clave de cifrado desde un archivo.

    Args:
        key_path (Path): Ruta al archivo de clave

    Returns:
        bytes: La clave cargada (debe ser 32 bytes)

    Raises:
        SystemExit: Si la clave no existe o es inválida
    """
    # Verificar que el archivo existe
    if not key_path.exists():
        log("error", f"No se encontró la clave en: {key_path}")
        sys.exit(1)

    if (
        os.path.getmtime(key_path) + KEY_MTIME_TOL
        <= datetime.datetime.now().timestamp()
    ):
        log(
            "warning"
            "! La clave que se va a utilizar es antigua ! Considera usar una nueva"
        )

    # Leer la clave del archivo

    with open(key_path, "rb") as key_file:
        key = key_file.read()

    # Validar que la clave tiene el tamaño correcto (32 bytes para AES-256)
    if len(key) != 32:
        log("error" , "Clave inválida: debe tener 32 bytes")
        sys.exit(1)

    return key


def list_keys(path: Path) -> list:
    if not path.exists():
        log("error" , f"No se encontró la ruta {path}")
        sys.exit(1)

    return list(f for f in os.listdir(str(path)) if f.endswith(".key"))


# ============================================================================
# METADATOS DEL ENCRIPTADO
# ============================================================================


def derive_nonce(salt: bytes, chunk_number: int):
    return hashlib.blake2s(
        chunk_number.to_bytes(8, "big"), key=salt, digest_size=12
    ).digest()


def write_metadata(file, *metadata):
    for d in metadata:
        file.write(d)


def read_metadata(file):
    magic = file.read(4)  # Hardcoded LEN
    if magic != MAGIC:
        log("warning", "Formato de archivo desconocido o corrupto")

    flags_byte = file.read(1)  # Harcoded LEN
    flags = flags_byte[0]

    if flags != FLAGS:
        log("warning", "Espacio reservado a flags ha sido corrompido")

    chunk_size = int.from_bytes(file.read(4), "big")  # Harcoded LEN

    salt = file.read(SALT_LEN)  # Configurable LEN
    if len(salt) != SALT_LEN:
        logger.warning("Archivo cifrado corrupto: salt inválido")

    name_len = int.from_bytes(file.read(2), "big")

    original_name = file.read(name_len).decode("utf-8")
    logger.info(original_name)

    return chunk_size, salt, original_name
    ...


# ============================================================================
# ENCRIPTADO / DESENCRIPTADO
# ============================================================================


def encrypt_file(
    key: bytes,
    file_path: Path,
    output_path: Path = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Path:
    """
    Cifra un archivo usando AES-GCM con procesamiento por chunks.

    Proceso de cifrado:
    1. Genera un nonce base aleatorio (12 bytes)
    2. Divide el archivo en chunks del tamaño especificado
    3. Para cada chunk:
       - Deriva un nonce único usando XOR con un contador
       - Asocia metadatos (nombre de archivo y número de chunk)
       - Cifra el chunk con AES-GCM
    4. Guarda: [nonce_base][chunk_cifrado_1][chunk_cifrado_2]...

    Args:
        key (bytes): Clave de cifrado de 32 bytes
        file_path (Path): Ruta al archivo a cifrar
        output_path (Path, optional): Ruta de salida (default: archivo.enc)
        chunk_size (int): Tamaño del chunk en bytes

    Returns:
        Path: Ruta al archivo cifrado

    Raises:
        SystemExit: Si el archivo no existe o hay un error durante el cifrado
    """
    # Validar que el archivo existe
    if not file_path.exists():
        log("error" , f"Archivo no encontrado: {file_path}")
        sys.exit(1)

    # Definir ruta de salida si no se especificó
    if output_path is None:
        output_path = Path(str(file_path) + ".enc")

    start_time = time.time()

    try:
        # Generar nonce base único para todo el archivo (12 bytes)
        salt = secrets.token_bytes(SALT_LEN)

        original_file_name = file_path.name.encode("utf-8")

        # Crear instancia de AES-GCM con la clave
        aesgcm = AESGCM(key)

        # Abrir archivo de entrada y salida
        with open(file_path, "rb") as f_in, open(output_path, "wb") as f_out:
            # Escribir nonce base al inicio del archivo cifrado
            # Este nonce se necesitará para descifrar
            write_metadata(
                f_out,
                MAGIC,
                bytes([FLAGS]),
                (chunk_size).to_bytes(4, "big"),
                salt,
                len(original_file_name).to_bytes(2, "big"),
                original_file_name,
            )

            # Barra de progreso
            pbar = tqdm(
                total=file_path.stat().st_size,
                unit="B",
                unit_scale=True,
                desc=f"Encriptando {file_path.name}",
                ncols=110,
            )

            chunk_number = 0
            # Procesar archivo por chunks
            while chunk := f_in.read(chunk_size):
                # Derivar nonce único para este chunk
                nonce = derive_nonce(salt, chunk_number)  # ! TODO: Derivación por HKDF

                # Crear datos asociados (AAD) para vincular chunk con su posición
                # Esto previene reordenamiento o sustitución de chunks
                associated_data = original_file_name + f":{chunk_number}".encode(
                    "utf-8"
                )

                # Cifrar el chunk con AES-GCM}:{chunk_numbe
                # El resultado incluye el chunk cifrado + tag de autenticación (16 bytes)
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, associated_data)

                # Escribir chunk cifrado al archivo
                f_out.write(encrypted_chunk)
                pbar.update(len(chunk))
                chunk_number += 1

        pbar.close()

        # Calcular estadísticas de rendimiento | # * Sustituído por la barra de progreso , queda reservado para debug o abierto a futuras implementaciones
        elapsed, size = return_status(start_time, file_path)
        log( "info", 
            f"✓ Archivo cifrado en {elapsed:.2f}s ({size:.1f} MB, {size / elapsed:.1f} MB/s) guardado en: {output_path}"
        )

        return output_path

    except KeyboardInterrupt:
        # Manejo de interrupción por usuario (Ctrl+C)
        log("error" , "\n[!] Cifrado interrumpido")
        if output_path.exists():
            output_path.unlink()  # Eliminar archivo parcial
        sys.exit(1)
    except Exception as e:
        # Manejo de otros errores
        log("error" , f"[!] Error durante el cifrado: {e}")
        if output_path.exists():
            output_path.unlink()  # Eliminar archivo corrupto
        raise


def decrypt_file(
    key: bytes,
    encrypted_file_path: Path,
    output_path: Path = None,
) -> Path:
    """
    Descifra un archivo cifrado con AES-GCM.

    Proceso de descifrado:
    1. Lee el nonce base del inicio del archivo
    2. Procesa el archivo por chunks
    3. Para cada chunk:
       - Deriva el nonce usando el mismo método que en el cifrado
       - Verifica el tag de autenticación
       - Descifra el chunk
    4. Detecta automáticamente manipulación mediante InvalidTag exception

    Args:
        key (bytes): Clave de descifrado de 32 bytes
        encrypted_file_path (Path): Ruta al archivo cifrado
        output_path (Path, optional): Ruta de salida (default: quita .enc)
        chunk_size (int): Tamaño del chunk en bytes

    Returns:
        Path: Ruta al archivo descifrado

    Raises:
        SystemExit: Si el archivo no existe, la clave es incorrecta,
                    o el archivo ha sido manipulado
    """
    # Validar que el archivo existe
    if not encrypted_file_path.exists():
        log("error" , f"Archivo no encontrado: {encrypted_file_path}")
        sys.exit(1)

    # Definir ruta de salida si no se especificó
    if output_path is None:
        output_path = Path(
            str(encrypted_file_path).replace(".enc", ".dec")
        )  # Mismo directorio de trabajo, cambiando la extensión

    start_time = time.time()

    try:
        # Crear instancia de AES-GCM con la clave
        aesgcm = AESGCM(key)

        # Abrir archivo cifrado y archivo de salida ( Descifrado )
        with open(encrypted_file_path, "rb") as f_in, open(output_path, "wb") as f_out:
            # Leer nonce base del inicio del archivo
            chunk_size, salt, original_file_name = read_metadata(f_in)
            logger.info(original_file_name)

            pbar = tqdm(
                total=encrypted_file_path.stat().st_size,
                unit="B",
                unit_scale=True,
                desc=f"Desencriptando {encrypted_file_path.name}",
                ncols=110,
            )

            chunk_number = 0
            # Procesar archivo por chunks
            while True:
                # Derivar con el mismo salt ( leído del archivo ) y el mismo nº de chunk
                nonce = derive_nonce(salt, chunk_number)

                # Leer chunk cifrado (datos + tag de autenticación de 16 bytes)
                encrypted_chunk = f_in.read(chunk_size + TAG_SIZE)
                if not encrypted_chunk:
                    break  # Fin del archivo

                # Recrear datos asociados (deben ser idénticos a los del cifrado)
                associated_data = f"{original_file_name}:{chunk_number}".encode("utf-8")

                # Descifrar chunk y verificar tag de autenticación
                # Si el tag no coincide, lanza InvalidTag exception
                decrypted_chunk = aesgcm.decrypt(
                    nonce, encrypted_chunk, associated_data
                )

                # Escribir chunk descifrado
                f_out.write(decrypted_chunk)
                pbar.update(len(encrypted_chunk))
                chunk_number += 1

        pbar.close()

        elapsed, size = return_status(start_time, output_path)
        log("info",
            f"✓ Archivo {output_path} descifrado en {elapsed:.2f}s ({size:.1f} MB, {size / elapsed:.1f} MB/s)", True
        )

        return output_path

    except InvalidTag:
        # El tag de autenticación no coincide: clave incorrecta o archivo manipulado
        log("error", "[!] Error: Clave incorrecta o archivo manipulado")
        if output_path.exists():
            output_path.unlink()  # Eliminar archivo corrupto
        sys.exit(1)
    except Exception as e:
        # Otros errores (archivo corrupto, etc.)
        log("error" , f"[!] Error durante el descifrado: {e}")
        if output_path.exists():
            output_path.unlink()
        sys.exit(1)


# ============================================================================
# VERIFICACIÓN Y POST-ENCRIPTADO
# ============================================================================


def calculate_hash(file_path: Path, chunk_size: int = 1 * 1024 * 1024) -> str:
    """
    Calcula el hash SHA-256 de un archivo procesándolo por chunks.

    Args:
        file_path (Path): Ruta al archivo
        chunk_size (int): Tamaño del chunk para procesar (default: 1 MB)

    Returns:
        str: Hash SHA-256 en formato hexadecimal
    """
    hash_obj = hashlib.sha256()

    # Leer y procesar el archivo por chunks
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


# ? No me gusta esta función
def rename_dec_file(decrypted_path: Path, keep_copy: bool = True) -> Path:
    """
    Renombra un archivo .dec eliminando la extensión y opcionalmente
    mantiene una copia de respaldo.

    Args:
        decrypted_path (Path): Ruta al archivo .dec
        keep_copy (bool): Si True, mantiene una copia con extensión .dec

    Returns:
        Path: Nueva ruta sin la extensión .dec
    """
    # Verificar que el archivo tiene extensión .dec
    if not str(decrypted_path).endswith(".dec"):
        return decrypted_path

    # Calcular ruta final (sin extensión .dec)
    final_path = Path(str(decrypted_path).replace(".dec", ""))

    if keep_copy:
        # Copiar el archivo (mantiene el .dec original como respaldo)
        import shutil

        shutil.copy2(decrypted_path, final_path)
        log("error", f"✓ Archivo copiado a: {final_path}")
        log("error", f"✓ Copia de respaldo mantenida en: {decrypted_path}")
    else:
        # Solo renombrar (mueve el archivo, no mantiene copia)
        decrypted_path.rename(final_path)
        log("ingo", f"✓ Archivo renombrado a: {final_path}")

    return final_path


def verify_integrity(
    original_path: Path, decrypted_path: Path, delete: bool = False
) -> bool:
    """
    Verifica la integridad de un archivo descifrado comparando hashes SHA-256.

    Args:
        original_path (Path): Ruta al archivo original (antes de cifrar)
        decrypted_path (Path): Ruta al archivo descifrado
        delete_dec (bool): Si True, elimina el archivo .dec después de verificar

    Returns:
        bool: True si los archivos son idénticos, False en caso contrario
    """
    logger.info("Verificando integridad...")

    # Validar que ambos archivos existen
    if not original_path.exists():
        log("error", f"Archivo original no encontrado: {original_path}")
        return False

    if not decrypted_path.exists():
        log("error", f"Archivo descifrado no encontrado: {decrypted_path}")
        return False

    # Calcular hashes SHA-256 de ambos archivos
    original_hash = calculate_hash(original_path)
    decrypted_hash = calculate_hash(decrypted_path)

    # Comparar hashes
    if original_hash == decrypted_hash:
        log("info", "✓ Integridad verificada: Los archivos son idénticos")
        log("info", f"  Hash SHA-256: {original_hash}")

        # Eliminar archivo .dec si se solicitó y la verificación fue exitosa
        if delete and str(decrypted_path).endswith(".dec"):
            try:
                decrypted_path.unlink()
                log("info" , f"✓ Archivo temporal .dec eliminado: {decrypted_path}")
            except Exception as e:
                logger("warning", f"No se pudo eliminar el archivo .dec: {e}")

        return True
    else:
        # Los hashes no coinciden: los archivos difieren
        log("error", "[!] FALLO DE INTEGRIDAD: Los archivos difieren")
        log("error",
            f"  Hash original:   {original_hash}\n  Hash descifrado: {decrypted_hash}"
        )
        return False


# ============================================================================
# ============================================================================


def main():
    """
    Función principal que coordina la ejecución del programa.

    Flujo:
    1. Parsea argumentos de línea de comandos
    2. Configura logging
    3. Ejecuta el comando solicitado (genkey/encrypt/decrypt/verify)
    4. Maneja errores y excepciones
    """
    # Parsear argumentos
    args = parse_args()

    # Configurar logging (consola y/o archivo)
    setup_logging(args.log_file)

    # Convertir ruta de clave a Path object
    key_path = Path(args.keyfile)

    try:
        # ---- Comando: genkey ----
        if args.command == "genkey":
            force = getattr(args, "force", False)
            gen_key(key_path, force=force)

        if args.command == "listkeys":
            path = Path(args.path)
            keys = list_keys(path)
            if keys:
                log("info", f"Llaves encontradas en {path}: {keys}")
            else:
                log("info" , f"No se encontraron llaves en {path}")

        # ---- Comando: encrypt ----
        elif args.command == "encrypt":
            # Si no existe la clave, generarla automáticamente
            if not key_path.exists():
                log("warning", 
                    f"Clave no encontrada, generando una nueva en {key_path}..."
                )
                gen_key(key_path)

            # Cargar clave y cifrar archivo
            key = load_key(key_path)
            file_path = Path(args.file)
            output_path = Path(args.output) if args.output else None
            log("info", f"Cifrando archivo {file_path} con llave {key_path}")
            encrypt_file(key, file_path, output_path, args.chunk_size)

        # ---- Comando: decrypt ----
        elif args.command == "decrypt":
            # Cargar clave y descifrar archivo
            key = load_key(key_path)
            encrypted_path = Path(args.file)
            output_path = Path(args.output) if args.output else None
            decrypted_path = decrypt_file(key, encrypted_path, output_path)

            # Renombrar archivo descifrado (mantener copia .dec como respaldo)
            final_path = rename_dec_file(decrypted_path, keep_copy=True)

            # Verificación de integridad si se solicita
            if args.verify:
                # Calcular ruta del archivo original
                original_path = Path(str(encrypted_path).replace(".enc", ""))

                if original_path.exists():
                    # Verificar integridad
                    delete_dec = getattr(args, "delete", False)
                    success = verify_integrity(
                        original_path, final_path, delete_dec=False
                    )

                    # Si verificación OK y se solicitó --delete, eliminar copia .dec
                    if success and delete_dec:
                        try:
                            decrypted_path.unlink()
                            log("info",
                                f"✓ Copia de respaldo .dec eliminada: {decrypted_path}"
                            )
                        except Exception as e:
                            log("warning",f"No se pudo eliminar la copia .dec: {e}")
                    elif not success:
                        logger.warning(
                            "La verificación falló, se mantiene la copia .dec para inspección"
                        )
                else:
                    # No se puede verificar sin archivo original
                    log("warning", 
                        f"No se encontró el archivo original para verificar: {original_path}"
                    )
                    log("warning", "Se mantiene la copia .dec")

        # ---- Comando: verify ----
        elif args.command == "verify":
            original_path = Path(args.original)
            decrypted_path = Path(args.decrypted)
            verify_integrity(original_path, decrypted_path, delete_dec=False)

    except KeyboardInterrupt:
        # Manejo de interrupción por usuario (Ctrl+C)
        log("error", "\n[!] Operación interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        # Manejo de errores generales
        log("error", f"[!] Error: {e}")
        sys.exit(1)


# ============================================================================
# ============================================================================

# Punto de entrada del script
if __name__ == "__main__":
    main()
