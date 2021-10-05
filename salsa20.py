import nacl.secret
import nacl.utils
import nacl.pwhash
from typing import Optional

class salsa20(object):
    # https://authmane512.medium.com/how-to-securely-encrypt-data-in-python-with-nacl-library-591d847e5789
    def __init__(self, password: str):
        self.password = password.encode('utf-8')
        self.salt_size = nacl.pwhash.argon2i.SALTBYTES
        self.kdf = nacl.pwhash.argon2i.kdf

    def _make_new_secretbox(self, salt: Optional[bytes] = None):
        if salt is None:
            self.salt = nacl.utils.random(self.salt_size)
        else:
            self.salt = salt
        self.key = self.kdf(nacl.secret.SecretBox.KEY_SIZE, self.password, self.salt)
        self.box = nacl.secret.SecretBox(self.key)

    def encrypt(self, raw: bytes) -> bytes:
        self._make_new_secretbox()
        x = self.box.encrypt(raw)
        return self.salt + x

    def encrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as in_file, open(outfile, 'wb') as out_file:
            out_file.write(self.encrypt(in_file.read()))

    def decrypt(self, enc: bytes) -> bytes:
        self._make_new_secretbox(salt=enc[:self.salt_size])
        return self.box.decrypt(enc[self.salt_size:])

    def decrypt_file(self, infile: str, outfile: str):
        with open(infile, 'rb') as in_file, open(outfile, 'wb') as out_file:
            out_file.write(self.decrypt(in_file.read()))

