
# ARCHIVOS

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import secrets
from pathlib import Path
import os
import time
import hashlib


test_path = Path.home() / 'Dev' / 'CryptoPython' / '.secret' / 'secret.key'   # Ruta de prueba para desarrollo

#default_path = Path.home() / '.secret' / 'secret.key'





def gen_key() -> bytes:
    '''
    Genera una llave de 256 bits para AES256 y la guarda en un archivo del directorio actual con permisos seguros
    ---
    returns: key (bytes): La clave generada
    '''
    key = secrets.token_bytes(32)                       # Generamos una clave de 32 bytes para AES256
    key_path = test_path                                # Establecemos la ruta predeterminada al archivo de la clave
    key_path.parent.mkdir(exist_ok=True, mode=0o700)    # Creamos el directiorio si no existe, con permisos reservados al propierario

    with open(key_path, 'wb') as keyf:
        keyf.write(key)
    os.chmod(key_path, 0o600)                           # Ajustamos los permisos del archivo tras escribir en él
    return key

def load_key() -> bytes:
    '''
    Carga una clave de el archivo, si no existe, crea una clave nueva con `gen_key` 
    ---
    returns: key ( bytes )
    '''
    key_path = test_path
    if not key_path.exists():                           # Si no existe el archivo, generamos una nueva clave
        print("No se ha encontrado la clave, generando una nueva...")
        return gen_key()

    with open(key_path, 'rb') as keyf:                  # Leemos la clave desde el archivo
        return keyf.read()   


def encrypt(key, message):
    nonce = secrets.token_bytes(12)                     # Número único aleatorio de 12 bytes para cada cifrado. No es secreto 
    ciphertext = nonce + AESGCM(key).encrypt(nonce, message.encode(), b"")
    return ciphertext

def decrypt(key, ciphertext):
    try:
        if len(ciphertext) < 12:
            raise ValueError("El texto cifrado es demasiado corto para ser válido.")
        return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], b"").decode('utf-8')   # Decodificamos los bytes a string
    except InvalidTag:
        print("[!] La clave es incorrecta o el mensaje ha sido manipulado [!].")
        return None
    except UnicodeDecodeError:
        print("[!] El mensaje descifrado no es válido UTF-8 [!].")
        return None
    except Exception as e:
        print(f"[!] Ha ocurrido un error: {e} [!]")
        return None

print(encrypt(load_key(),"Hola"))
print(decrypt(load_key(), encrypt(load_key(),"Hola")))
