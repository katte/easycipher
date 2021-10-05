from typing import Union, Optional
import base64
import_mode = 'local'
def import_local_module(module):
    def try_or(func, default=None, expected_exc=(Exception,)):
        global import_mode
        try:
            exec(func, globals())
            import_mode = 'local'
        except expected_exc:
            if default is not None:
                exec(default, globals())
                import_mode = 'path'
    try_or(f"from . {module} import {module}", default=f"import {module}")

import_local_module('aes_256_cbc')
import_local_module('openssl___aes_256_cbc')
import_local_module('salsa20')


class EasyCipher(object):
    VERSION = '1.2.1'
    AUTHOR = 'Marco Catellani (marco@catellanielettronica.it)'
    LAST_MODIFIED = '05/10/2021'
    MODIFIED_BY = 'Marco Catellani (marco@catellanielettronica.it)'
    CHANGELOG = ''''''
    DESCRIPTION = ''''''
    
    def __init__(self, password: str, algo: str = 'salsa20'):
        if algo not in self.supported_algos():
            return None
        self.algo = algo
        self.password = password
        self.__crypto_obj = None

    @staticmethod
    def supported_algos():
        return ['aes_256_cbc', 'openssl>=1.1.0_aes_256_cbc', 'openssl<1.1.0_aes_256_cbc', 'salsa20']

    def __init_crypto_obj(self):
        if self.__crypto_obj is None:
            if self.algo.lower() == 'aes_256_cbc':
                pre = 'aes_256_cbc.' if import_mode == 'path' else ''
                self.__crypto_obj = eval(f'{pre}aes_256_cbc(self.password)')
            elif self.algo.lower() == 'openssl>=1.1.0_aes_256_cbc':
                pre = 'openssl___aes_256_cbc.' if import_mode == 'path' else ''
                self.__crypto_obj = eval(f'{pre}openssl___aes_256_cbc(self.password)')
            elif self.algo.lower() == 'openssl<1.1.0_aes_256_cbc':
                pre = 'openssl___aes_256_cbc.' if import_mode == 'path' else ''
                self.__crypto_obj = eval(f'{pre}openssl___aes_256_cbc(self.password)')
                self.__crypto_obj.openssl_version_minor_of_1_1_0 = True
            elif self.algo.lower() == 'salsa20':
                pre = 'salsa20.' if import_mode == 'path' else ''
                self.__crypto_obj = eval(f'{pre}salsa20(self.password)')

    def get_key(self) -> Optional[bytes]:
        try:
            self.__init_crypto_obj()
            return self.__crypto_obj.key
        except:
            pass
        return None

    def get_last_iv(self) -> Optional[bytes]:
        try:
            self.__init_crypto_obj()
            return self.__crypto_obj.last_iv
        except:
            pass
        return None
    
    def encrypt(self, raw: bytes) -> Optional[bytes]:
        try:
            self.__init_crypto_obj()
            return self.__crypto_obj.encrypt(raw)
        except Exception as ex:
            pass
        return None

    def encryptB64(self, raw: bytes) -> Optional[str]:
        return base64.b64encode(self.encrypt(raw))

    def encrypt_file(self, filein: str, fileout: str) -> bool:
        try:
            self.__init_crypto_obj()
            self.__crypto_obj.encrypt_file(filein, fileout)
            return True
        except:
            pass
        return False

    def decrypt(self, enc: bytes) -> Optional[bytes]:
        try:
            self.__init_crypto_obj()
            return self.__crypto_obj.decrypt(enc)
        except:
            pass
        return None

    def decryptB64(self, enc: str) -> Optional[bytes]:
        return self.decrypt(base64.b64decode(enc))

    def decrypt_file(self, filein: str, fileout: str) -> bool:
        try:
            self.__init_crypto_obj()
            self.__crypto_obj.decrypt_file(filein, fileout)
            return True
        except:
            pass
        return False
