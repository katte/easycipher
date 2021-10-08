from typing import Union, Optional
import hashlib

def md5(raw:bytes) -> Optional[bytes]:
    return hashlib.md5(raw).digest()

def md5_file(filein: str) -> Optional[bytes]:
    hash = hashlib.md5()
    with open(filein, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.digest()

def sha256(raw:bytes) -> Optional[bytes]:
    return hashlib.sha256(raw).digest()

def sha256_file(filein: str) -> Optional[bytes]:
    hash = hashlib.sha256()
    with open(filein, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.digest()