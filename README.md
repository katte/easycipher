# easycipher
Easy class for crypt, decrypt, hash, sign data and files, with many algorithm and no stress :)

Supported algorithms: 
* Crypt / Decrypt of data and files:
  * AES 256 CBC
  * openssl >= 1.1.0 AES 256 CBC 
  * openssl <  1.1.0 AES 256 CBC
  * Salsa20 (default)
* Hash of data, files and folders:
  * MD5
  * SHA1
  * SHA256 (default)
* Sign of data:
  * PKCS#1 V1.5
  * RSASSA PSS (default)

Check test.py for usages.
