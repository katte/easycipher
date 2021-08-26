from os import urandom
from hashlib import md5, sha256
from Crypto.Cipher import AES
import io

class openssl___aes_256_cbc(object):
    def __init__(self, password: str):
        self.bs = AES.block_size
        self.password = password
        self.key = b''
        self.last_iv = b''
        self.salt_header = 'Salted__'
        self.key_length = 32
        self.openssl_version_minor_of_1_1_0 = False

    def derive_key_and_iv(self, salt: bytes):
        d = d_i = b''  # changed '' to b''
        while len(d) < self.key_length + self.bs:
            # changed password to str.encode(password)
            if self.openssl_version_minor_of_1_1_0:
                df = md5
            else:
                df = sha256
            d_i = df(d_i + self.password.encode('utf-8') + salt).digest()
            d += d_i
        self.key = d[:self.key_length]
        self.last_iv = d[self.key_length:self.key_length + self.bs]
        return self.key, self.last_iv
    
    def encrypt(self, raw: bytes) -> bytes:
        in_file = io.BytesIO(raw)
        out_file = io.BytesIO()
        self._encrypt_file(in_file, out_file)
        out_file.seek(0)
        return out_file.read()
    
    def encrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as in_file:
            with open(outfile, 'wb') as out_file:
                self._encrypt_file(in_file, out_file)
    
    def _encrypt_file(self, in_file: object, out_file: object):
        # replaced Crypt.Random with os.urandom
        salt = urandom(self.bs - len(self.salt_header))
        key, iv = self.derive_key_and_iv(salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write(str.encode(self.salt_header) + salt)
        finished = False
        while not finished:
            chunk = in_file.read(1024 * self.bs)
            if len(chunk) == 0 or len(chunk) % self.bs != 0:
                padding_length = (self.bs - len(chunk) % self.bs) or self.bs
                # changed right side to str.encode(...)
                chunk += str.encode(
                    padding_length * chr(padding_length))
                finished = True
            out_file.write(cipher.encrypt(chunk))
    
    def decrypt(self, enc: bytes) -> bytes:
        in_file = io.BytesIO(enc)
        out_file = io.BytesIO()
        self._decrypt_file(in_file, out_file)
        out_file.seek(0)
        return out_file.read()
    
    def decrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as in_file:
            with open(outfile, 'wb') as out_file:
                self._decrypt_file(in_file, out_file)
    
    def _decrypt_file(self, in_file: object, out_file: object):
        salt = in_file.read(self.bs)[len(self.salt_header):]
        key, iv = self.derive_key_and_iv(salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(
                in_file.read(1024 * self.bs))
            if len(next_chunk) == 0:
                padding_length = chunk[-1]  # removed ord(...) as unnecessary
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(bytes(x for x in chunk))  # changed chunk to bytes(...)
