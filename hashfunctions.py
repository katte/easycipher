from typing import Union, Optional
import hashlib

def md5(raw:bytes, outputformat: str = 'bytes') -> Optional[Union[bytes, str]]:
    b = hashlib.md5(raw).digest()
    if outputformat == 'bytes':
        return b
    elif outputformat == 'hex':
        return convert_hash_bytes_to_hexstring(b)

def md5_file(filein: str, outputformat: str = 'bytes') -> Optional[Union[bytes, str]]:
    hash = hashlib.md5()
    with open(filein, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    b = hash.digest()
    if outputformat == 'bytes':
        return b
    elif outputformat == 'hex':
        return convert_hash_bytes_to_hexstring(b)

def sha(bit:int, raw:bytes, outputformat: str = 'bytes') -> Optional[Union[bytes, str]]:
    if bit == 1:
        b = hashlib.sha1(raw).digest()
    elif bit == 256:
        b = hashlib.sha256(raw).digest()
    if outputformat == 'bytes':
        return b
    elif outputformat == 'hex':
        return convert_hash_bytes_to_hexstring(b)

def sha_file(bit:int, filein: str, outputformat: str = 'bytes') -> Optional[Union[bytes, str]]:
    if bit == 1:
        hash = hashlib.sha1()
    elif bit == 256:
        hash = hashlib.sha256()
    with open(filein, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    b = hash.digest()
    if outputformat == 'bytes':
        return b
    elif outputformat == 'hex':
        return convert_hash_bytes_to_hexstring(b)

def convert_hash_bytes_to_hexstring(inb:Union[bytes, list], uppercase:bool=False) -> str:
    if uppercase:
        return ''.join([f'{x:02X}' for x in inb])
    else:
        return ''.join([f'{x:02x}' for x in inb])