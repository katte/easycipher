from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import binascii

def generate_keys(bits=2048):
    keypair = RSA.generate(bits)
    pubkey = keypair.publickey()
    privkey = keypair.export_key()
    pubkey = pubkey.export_key()
    return (privkey, pubkey)

def check_pubkey_with_privkey(pubkey: str, privkey: str) -> bool:
    privkey = RSA.import_key(privkey)
    valid_pubkey = RSA.import_key(pubkey)
    given_pubkey = RSA.import_key(pubkey)
    if valid_pubkey == given_pubkey:
        return True
    return False

def get_message_signature(privkey: str, msg: bytes) -> str:
    # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
    privkey = RSA.import_key(privkey)
    hash = SHA256.new(msg)
    signer = pss.new(privkey)
    signature = signer.sign(hash)
    return binascii.hexlify(signature)

def verify_message(pubkey: str, msg: bytes, signature: str):
    # Verify valid PKCS#1 v1.5 signature (RSAVP1)
    hash = SHA256.new(msg)
    pubkey = RSA.import_key(pubkey)
    verifier = pss.new(pubkey)
    try:
        verifier.verify(hash, binascii.unhexlify(signature))
        return True
    except:
        return False
