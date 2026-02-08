from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import base64, time

# ---------- HASH ----------
def sha256_hash(text):
    return SHA256.new(text.encode()).hexdigest()

# ---------- AES ----------
def aes_encrypt(text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    return {
        "algo": "AES",
        "cipher": base64.b64encode(ciphertext).decode(),
        "key": base64.b64encode(key).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode()
    }

def aes_decrypt(cipher, key, nonce):
    cipher_obj = AES.new(
        base64.b64decode(key),
        AES.MODE_EAX,
        nonce=base64.b64decode(nonce)
    )
    return cipher_obj.decrypt(base64.b64decode(cipher)).decode()

# ---------- DES ----------
def des_encrypt(text):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    return {
        "algo": "DES",
        "cipher": base64.b64encode(ciphertext).decode(),
        "key": base64.b64encode(key).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode()
    }

def des_decrypt(cipher, key, nonce):
    cipher_obj = DES.new(
        base64.b64decode(key),
        DES.MODE_EAX,
        nonce=base64.b64decode(nonce)
    )
    return cipher_obj.decrypt(base64.b64decode(cipher)).decode()

# ---------- RSA ----------
def rsa_encrypt(text):
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key.publickey())
    ciphertext = cipher.encrypt(text.encode())

    return {
        "algo": "RSA",
        "cipher": base64.b64encode(ciphertext).decode(),
        "private_key": base64.b64encode(key.export_key()).decode()
    }

def rsa_decrypt(cipher, private_key):
    key = RSA.import_key(base64.b64decode(private_key))
    cipher_obj = PKCS1_OAEP.new(key)
    return cipher_obj.decrypt(base64.b64decode(cipher)).decode()
