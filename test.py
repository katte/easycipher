import os
import random
import string
import base64
from easycipher import EasyCipher

if __name__ == '__main__':
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))  # https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits
    print(f'Key: {key}')
    message = ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(1, 100)))
    print(f'Message to encrypt: {message}')
    if True:
        for algo in EasyCipher.supported_algos():
            print(f'\n\n\n=== {algo} ===')
            ec_enc = EasyCipher(algo=algo, password=key)
            ec_dec = EasyCipher(algo=algo, password=key)
            print(f'Encrypt "{message}"')
            enc = ec_enc.encrypt(message.encode('utf-8'))
            print(f'Bytearray: {enc}')
            print(f'Hex: {enc.hex(sep=" ")}')
            encB64 = ec_enc.encryptB64(message.encode('utf-8'))
            print(f'B64: {encB64}')
            print('\n')
            print(f'Decrypt Bytearray: {enc}')
            print(f'Bytearray : {ec_dec.decrypt(enc)}')
            print(f'Decrypt B64: {encB64}')
            print(f'Bytearray: {ec_dec.decryptB64(encB64)}')

            infile = 'infile.txt'
            outfile = 'outfile.txt'
            with open(infile, 'w') as f:
                f.write(message)
            print('Encrypt file')
            ec_enc.encrypt_file(infile, outfile)
            with open(outfile, 'rb') as f:
                print(f.read())
            os.remove(infile)
            print('Decrypt file')
            ec_dec.decrypt_file(outfile, infile)
            with open(infile, 'r') as f:
                print(f.read())
            os.remove(infile)
            os.remove(outfile)

    if True:
        for algo in EasyCipher.supported_hash_algos():
            print(f'\n\n\n=== {algo} ===')
            print(f'Hash "{message}"')
            enc = EasyCipher.hash(message.encode('utf-8'), algo)
            print(f'Bytearray: {enc}')
            print(f'Hex: {enc.hex(sep=" ")}')
            print('\n')
            infile = 'infile.txt'
            with open(infile, 'w') as f:
                f.write(message)
            print('Hash file')
            enc = EasyCipher.hash_file(infile, algo)
            print(f'Bytearray: {enc}')
            print(f'Hex: {enc.hex(sep=" ")}')
            os.remove(infile)

