import hashlib
from _hashlib import HASH as Hash
from pathlib import Path
from typing import Union
try:
    from . import hashfunctions
except:
    import hashfunctions

def _hash_update_from_file(filename: Union[str, Path], hash: Hash) -> Hash:
    assert Path(filename).is_file()
    with open(str(filename), "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash

def _hash_update_from_dir(directory: Union[str, Path], hash: Hash) -> Hash:
    assert Path(directory).is_dir()
    for path in sorted(Path(directory).iterdir(), key=lambda p: str(p).lower()):
        hash.update(path.name.encode())
        if path.is_file():
            hash = _hash_update_from_file(path, hash)
        elif path.is_dir():
            hash = _hash_update_from_dir(path, hash)
    return hash


def _hash_update_from_dirs(dirs: list, hash: Hash) -> Hash:
    for directory in dirs:
        assert Path(directory).is_dir()
        for path in sorted(Path(directory).iterdir(), key=lambda p: str(p).lower()):
            hash.update(path.name.encode())
            if path.is_file():
                hash = _hash_update_from_file(path, hash)
            elif path.is_dir():
                hash = _hash_update_from_dir(path, hash)
    return hash

def md5_directory(directory: Union[str, Path], outputformat: str = 'bytes') -> str:
    b = _hash_update_from_dir(directory, hashlib.md5()).digest()
    if outputformat == 'bytes':
        return b
    elif outputformat == 'hex':
        return hashfunctions.convert_hash_bytes_to_hexstring(b)    

def md5_directories(dirs: list, outputformat: str = 'bytes') -> str:
    b = _hash_update_from_dirs(dirs, hashlib.md5()).digest()
    if outputformat == 'bytes':
        return b
    elif outputformat == 'hex':
        return hashfunctions.convert_hash_bytes_to_hexstring(b)      

def sha_directory(bit:int, directory: Union[str, Path], outputformat: str = 'bytes') -> str:
    if bit == 1:
        hashfun = hashlib.sha1
    elif bit == 256:
        hashfun = hashlib.sha256
    b = _hash_update_from_dir(directory, hashfun()).digest()
    if outputformat == 'bytes':
        return b
    elif outputformat == 'hex':
        return hashfunctions.convert_hash_bytes_to_hexstring(b)      

def sha_directories(bit:int, dirs: list, outputformat: str = 'bytes') -> str:
    if bit == 1:
        hashfun = hashlib.sha1
    elif bit == 256:
        hashfun = hashlib.sha256    
    b = _hash_update_from_dirs(dirs, hashfun()).digest()
    if outputformat == 'bytes':
        return b
    elif outputformat == 'hex':
        return hashfunctions.convert_hash_bytes_to_hexstring(b)      
