from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import os
import binascii
from Crypto.Util.Padding import pad, unpad

def des_encrypt(message, key, iv, padding_scheme):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    if padding_scheme == "pkcs7":
        padded_data = pad(message, DES3.block_size)
    elif padding_scheme == "zero_padding":
        padded_data = message + b'\0' * (DES3.block_size - len(message) % DES3.block_size)
    else:
        raise ValueError("Invalid padding scheme")

    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def des_decrypt(ciphertext, key, padding_scheme):
    iv = ciphertext[:DES3.block_size]
    ciphertext = ciphertext[DES3.block_size:]

    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(ciphertext)

    if padding_scheme == "pkcs7":
        unpadded_data = unpad(decrypted_data, DES3.block_size)
    elif padding_scheme == "zero_padding":
        unpadded_data = decrypted_data.rstrip(b'\0')
    else:
        raise ValueError("Invalid padding scheme")

    return unpadded_data

# Example usage:
key = get_random_bytes(24)  # 192-bit key for DES3
iv = get_random_bytes(8)    # 64-bit IV for DES3
message = b"DES encryption lab test"

# PKCS7 Padding
ciphertext_pkcs7 = des_encrypt(message, key, iv, padding_scheme="pkcs7")
decrypted_message_pkcs7 = des_decrypt(ciphertext_pkcs7, key, padding_scheme="pkcs7")

# Zero Padding
ciphertext_zero_padding = des_encrypt(message, key, iv, padding_scheme="zero_padding")
decrypted_message_zero_padding = des_decrypt(ciphertext_zero_padding, key, padding_scheme="zero_padding")

print("Original Message:", message.decode())
print("Ciphertext (PKCS7):", binascii.hexlify(ciphertext_pkcs7).decode())
print("Decrypted Message (PKCS7):", decrypted_message_pkcs7.decode())

print("\nCiphertext (Zero Padding):", binascii.hexlify(ciphertext_zero_padding).decode())
print("Decrypted Message (Zero Padding):", decrypted_message_zero_padding.decode())
