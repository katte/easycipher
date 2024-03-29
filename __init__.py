from typing import Union, Optional
import base64
try:
    from . import aes_256_cbc
    from . import openssl___aes_256_cbc
    from . import salsa20
    from . import hashfunctions
    from . import hashfunctions_for_directories
    from . import pkcs1_v1_5
    from . import rsassa_pss
except:
    import aes_256_cbc
    import openssl___aes_256_cbc
    import salsa20
    import hashfunctions
    import hashfunctions_for_directories
    import pkcs1_v1_5
    import rsassa_pss



class EasyCipher:
    VERSION = '1.8.0'
    AUTHOR = 'Marco Catellani (katte82@gmail.com)'
    LAST_MODIFIED = '11/12/2023'
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
        return ['md5', 'sha1', 'sha256']

    @staticmethod
    def hash(raw: bytes, algo: str = 'sha256', outputformat: str = 'bytes') -> Optional[Union[bytes, str]]:
        if algo not in EasyCipher.supported_hash_algos():
            return None
        if algo == 'md5':
            return hashfunctions.md5(raw, outputformat)
        elif algo == 'sha1':
            return hashfunctions.sha(1, raw, outputformat)
        elif algo == 'sha256':
            return hashfunctions.sha(256, raw, outputformat)

    @staticmethod
    def hash_file(filein: str, algo: str = 'sha256', outputformat: str = 'bytes') -> Optional[Union[bytes, str]]:
        if algo not in EasyCipher.supported_hash_algos():
            return None
        if algo == 'md5':
            return hashfunctions.md5_file(filein, outputformat)
        elif algo == 'sha1':
            return hashfunctions.sha_file(1, filein, outputformat)
        elif algo == 'sha256':
            return hashfunctions.sha_file(256, filein, outputformat)

    @staticmethod
    def hash_directory(filein: str, algo: str = 'sha256', outputformat: str = 'bytes') -> Optional[Union[bytes, str]]:
        if algo not in EasyCipher.supported_hash_algos():
            return None
        if algo == 'md5':
            return hashfunctions_for_directories.md5_directory(filein, outputformat)
        elif algo == 'sha1':
            return hashfunctions_for_directories.sha_directory(1, filein, outputformat)
        elif algo == 'sha256':
            return hashfunctions_for_directories.sha_directory(256, filein, outputformat)

    @staticmethod
    def hash_directories(filein: str, algo: str = 'sha256', outputformat: str = 'bytes') -> Optional[Union[bytes, str]]:
        if algo not in EasyCipher.supported_hash_algos():
            return None
        if algo == 'md5':
            return hashfunctions_for_directories.md5_directories(filein, outputformat)
        elif algo == 'sha1':
            return hashfunctions_for_directories.sha_directories(1, filein, outputformat)
        elif algo == 'sha256':
            return hashfunctions_for_directories.sha_directories(256, filein, outputformat)

    @staticmethod
    def supported_sign_algos():
        return ['pkcs#1_1.5', 'rsassa_pss']

    @staticmethod
    def generate_key_for_sign_algo(algo: str = 'rsassa_pss'):
        if algo not in EasyCipher.supported_sign_algos():
            return None
        if algo == 'pkcs#1_1.5':
            return pkcs1_v1_5.generate_keys()
        elif algo == 'rsassa_pss':
            return rsassa_pss.generate_keys()
    
    @staticmethod
    def check_pubkey_with_privkey(pubkey: str, privkey: str, algo: str = 'rsassa_pss') -> bool:
        if algo not in EasyCipher.supported_sign_algos():
            return None
        if algo == 'pkcs#1_1.5':
            return pkcs1_v1_5.check_pubkey_with_privkey(pubkey, privkey)
        elif algo == 'rsassa_pss':
            return rsassa_pss.check_pubkey_with_privkey(pubkey, privkey)
    
    @staticmethod
    def get_message_signature(privkey: str, msg:bytes, algo: str = 'rsassa_pss') -> bytes:
        if algo not in EasyCipher.supported_sign_algos():
            return None
        if algo == 'pkcs#1_1.5':
            return pkcs1_v1_5.get_message_signature(privkey, msg)
        elif algo == 'rsassa_pss':
            return rsassa_pss.get_message_signature(privkey, msg)

    @staticmethod
    def verify_message(pubkey: str, msg:bytes, signature: str, algo: str = 'rsassa_pss') -> bool:
        if algo not in EasyCipher.supported_sign_algos():
            return None
        if algo == 'pkcs#1_1.5':
            return pkcs1_v1_5.verify_message(pubkey, msg, signature)
        elif algo == 'rsassa_pss':
            return rsassa_pss.verify_message(pubkey, msg, signature)
