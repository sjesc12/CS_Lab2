from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def aes_256_encrypt(message, key, iv, padding_scheme):
    backend = default_backend()
    
    if len(key) != 32:  # Ensure key is 256 bits
        raise ValueError("Key must be 256 bits")

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)

    if padding_scheme == "pkcs7":
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message) + padder.finalize()
    elif padding_scheme == "zero_padding":
        padded_data = message + b'\0' * (algorithms.AES.block_size - len(message) % algorithms.AES.block_size)
    else:
        raise ValueError("Invalid padding scheme")

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

def aes_256_decrypt(ciphertext, key, padding_scheme):
    backend = default_backend()
    
    if len(key) != 32:  # Ensure key is 256 bits
        raise ValueError("Key must be 256 bits")

    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)

    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    if padding_scheme == "pkcs7":
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        message = unpadder.update(padded_data) + unpadder.finalize()
    elif padding_scheme == "zero_padding":
        message = padded_data.rstrip(b'\0')
    else:
        raise ValueError("Invalid padding scheme")

    return message

# Example usage:
key = os.urandom(32)  # 256-bit key
iv = os.urandom(16)   # 128-bit IV
message = b"AES-256 encryption lab test"

# PKCS7 Padding
ciphertext_pkcs7 = aes_256_encrypt(message, key, iv, padding_scheme="pkcs7")
decrypted_message_pkcs7 = aes_256_decrypt(ciphertext_pkcs7, key, padding_scheme="pkcs7")

# Zero Padding
ciphertext_zero_padding = aes_256_encrypt(message, key, iv, padding_scheme="zero_padding")
decrypted_message_zero_padding = aes_256_decrypt(ciphertext_zero_padding, key, padding_scheme="zero_padding")

print("Original Message:", message.decode())
print("Ciphertext (PKCS7):", ciphertext_pkcs7.hex())
print("Decrypted Message (PKCS7):", decrypted_message_pkcs7.decode())

print("\nCiphertext (Zero Padding):", ciphertext_zero_padding.hex())
print("Decrypted Message (Zero Padding):", decrypted_message_zero_padding.decode())
