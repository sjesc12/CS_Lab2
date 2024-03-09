from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import hashlib
import sys
import binascii

def encrypt(plaintext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode, default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext) + encryptor.finalize()
    return ct

def decrypt(ciphertext, key, mode):
    method = algorithms.AES(key)
    cipher = Cipher(method, mode, default_backend())
    decryptor = cipher.decryptor()
    pl = decryptor.update(ciphertext) + decryptor.finalize()
    return pl

def pad(data, size=128):
    padder = padding.PKCS7(size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

def unpad(data, size=128):
    unpadder = padding.PKCS7(size).unpadder()
    unpadded_data = unpadder.update(data)
    unpadded_data += unpadder.finalize()
    return unpadded_data

def main():
    if len(sys.argv) != 3:
        print("Usage: python cipher01.py <plaintext> <key>")
        sys.exit(1)

    plaintext = sys.argv[1]
    key = hashlib.sha256(sys.argv[2].encode()).digest()

    print("Plaintext:", plaintext)

    plaintext = pad(plaintext.encode())

    print("After padding (CMS):", binascii.hexlify(bytearray(plaintext)))

    ciphertext = encrypt(plaintext, key, modes.ECB())
    print("Cipher (ECB):", binascii.hexlify(bytearray(ciphertext)))

    decrypted_data = decrypt(ciphertext, key, modes.ECB())
    decrypted_data = unpad(decrypted_data)
    print("Decrypted:", decrypted_data.decode())
if __name__ == "__main__":
    main()

