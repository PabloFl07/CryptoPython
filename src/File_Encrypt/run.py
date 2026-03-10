from keys import KeySource
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 , AESGCM


class Run:

    CIPHER_DISPATCH = {
            "aesgcm": AESGCM,
            "chacha": ChaCha20Poly1305,
        }

    @staticmethod
    def encrypt(in_file : Path, out_file : Path , key_source : KeySource, cipher_source : str, ):
        salt = key_source.get_salt() # Into the File Header
        key = key_source.get_key()
        
        cipher = Run.CIPHER_DISPATCH[cipher_source](key) # Instance of the cipher, ready to use


    @staticmethod
    def decrypt():
        raise NotImplementedError()
    
    @staticmethod
    def verify(original , decrypted , algorithm):
        raise NotImplementedError()
    
    @staticmethod
    def hash(file , algorithm):
        raise NotImplementedError()
    

