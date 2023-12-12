from typing import Union, Optional
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class aes_256_cbc(object):
    def __init__(self, key: str):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode('utf-8')).digest()
        self.last_iv = b''

    def encrypt(self, raw: bytes) -> bytes:
        raw = self._pad(raw)
        iv = Random.new().read(self.bs)        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        self.last_iv = iv
        return iv + cipher.encrypt(raw)

    def encrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as in_file:
            with open(outfile, 'wb') as out_file:
                out_file.write(self.encrypt(in_file.read()))

    def decrypt(self, enc: bytes) -> bytes:
        iv = enc[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        self.last_iv = iv
        return self._unpad(cipher.decrypt(enc[self.bs:]))

    def decrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as in_file:
            with open(outfile, 'wb') as out_file:
                out_file.write(self.decrypt(in_file.read()))

    def _pad(self, s):
        """
        padding to blocksize according to PKCS #5
        calculates the number of missing chars to BLOCK_SIZE and pads with
        ord(number of missing chars)
        @see: http://www.di-mgt.com.au/cryptopad.html
        @param s: string to pad
        @type s: string
        @rtype: string
        """    
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs).encode('utf-8')

    @staticmethod
    def _unpad(s):
        """
        unpadding according to PKCS #5
        @param s: string to unpad
        @type s: string
        @rtype: string
        """    
        return s[:-ord(s[len(s) - 1:])]