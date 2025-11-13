# Source - https://stackoverflow.com/a
# Posted by maxschlepzig, modified by community. See post 'Timeline' for change history
# Retrieved 2025-11-13, License - CC BY-SA 4.0




import hashlib


DEFAULT_CHUNK_SIZE2 = 1 * 1024* 1024 # 1MB
CHUNK_SIZE2 = DEFAULT_CHUNK_SIZE2
DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB
CHUNK_SIZE = DEFAULT_CHUNK_SIZE


def calculate_hash2(file_name):
    hash = hashlib.sha256()
    with open(file_name, 'rb') as f:
        while chunk:= f.read(CHUNK_SIZE2):
          hash.update(chunk)
    return hash.hexdigest()

print(calculate_hash2("hola.txt"))