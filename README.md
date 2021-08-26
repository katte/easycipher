# easycipher
Easy class for crypt and decrypt data and files, with many algorithm and no stress :)

Supported algorithms are: 'aes_256_cbc', 'openssl_aes_256_cbc', 'salsa20' (default)

usage:
> from easycipher import EasyCipher
> 
> ec_enc = EasyCipher(password?'mySecretPassword', algo='aes_256_cbc')
>
> message = b'My secret message'
> 
> encoded = ec_enc.encrypt(message)
> 
> original = ec_dec.decrypt(encoded)) 

there also have this APIs:

API | Description
--- | ---
supported_algos() | List of supported algorithms. Actual: 
encrypt(raw: bytes) -> Optional[bytes] | Encrypt a bytearray and return it in bytearray format
encryptB64(raw: bytes) -> Optional[str] | Encrypt a bytearray and return it in base64 format
encrypt_file(filein: str, fileout: str) -> bool | Encrypt a file and make a crypted file
decrypt(enc: bytes) -> Optional[bytes] | Decrypt a bytearray and return it in bytearray format
decryptB64(enc: str) -> Optional[bytes] | Decrypt a base64 string and return it in bytearray format
decrypt_file(filein: str, fileout: str) -> bool | Decrypt a file and make a decrypted file

Check test.py for other usages.
