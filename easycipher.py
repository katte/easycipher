from typing import Union, Optional
import base64
try:
    from . import aes_256_cbc
    from . import openssl___aes_256_cbc
    from . import salsa20
    from . import hashfunctions
    from . import pkcs1_v1_5
except:
    import aes_256_cbc
    import openssl___aes_256_cbc
    import salsa20
    import hashfunctions
    import pkcs1_v1_5



class EasyCipher:
    VERSION = '1.4.0'
    AUTHOR = 'Marco Catellani (katte82@gmail.com)'
    LAST_MODIFIED = '27/03/2023'
    MODIFIED_BY = 'Marco Catellani (katte82@gmail.com)'
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
                self.__crypto_obj = aes_256_cbc.aes_256_cbc(self.password)
            elif self.algo.lower() == 'openssl>=1.1.0_aes_256_cbc':
                self.__crypto_obj = openssl___aes_256_cbc.openssl___aes_256_cbc(self.password)
            elif self.algo.lower() == 'openssl<1.1.0_aes_256_cbc':
                self.__crypto_obj = openssl___aes_256_cbc.openssl___aes_256_cbc(self.password)
                self.__crypto_obj.openssl_version_minor_of_1_1_0 = True
            elif self.algo.lower() == 'salsa20':
                self.__crypto_obj = salsa20.salsa20(self.password)

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

    @staticmethod
    def supported_hash_algos():
        return ['md5', 'sha256']

    @staticmethod
    def hash(raw: bytes, algo: str = 'sha256') -> Optional[bytes]:
        if algo not in EasyCipher.supported_hash_algos():
            return None
        if algo == 'md5':
            return hashfunctions.md5(raw)
        elif algo == 'sha256':
            return hashfunctions.sha256(raw)

    @staticmethod
    def hash_file(filein: str, algo: str = 'sha256') -> Optional[bytes]:
        if algo not in EasyCipher.supported_hash_algos():
            return None
        if algo == 'md5':
            return hashfunctions.md5_file(filein)
        elif algo == 'sha256':
            return hashfunctions.sha256_file(filein)

    @staticmethod
    def supported_sign_algos():
        return ['PKCS#1 v1.5']

    @staticmethod
    def generate_key_for_sign_algo():
        return pkcs1_v1_5.generate_keys()
    
    @staticmethod
    def get_message_signature(privkey: str, msg:bytes) -> bytes:
        return pkcs1_v1_5.get_message_signature(privkey, msg)

    @staticmethod
    def verify_message(pubkey: str, msg:bytes, signature: str) -> bool:
        return pkcs1_v1_5.verify_message(pubkey, msg, signature)
