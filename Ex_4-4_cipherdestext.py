from Crypto.Cipher import DES
import hashlib
import binascii

def encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data

def pad(data, size=64):
    pad_size = size - (len(data) % size)
    padded_data = data + bytes([pad_size] * pad_size)
    return padded_data

def unpad(data, size=64):
    pad_size = data[-1]
    unpadded_data = data[:-pad_size]
    return unpadded_data

def main():
    plaintext = input("Enter plaintext: ")
    key = hashlib.md5(input("Enter key: ").encode()).digest()[:8]  # DES key is 8 bytes

    print("Plaintext:", plaintext)

    plaintext = pad(plaintext.encode())

    print("After padding (CMS):", binascii.hexlify(bytearray(plaintext)))

    ciphertext = encrypt(plaintext, key)
    print("Cipher (DES):", binascii.hexlify(bytearray(ciphertext)))

    decrypted_data = decrypt(ciphertext, key)
    decrypted_data = unpad(decrypted_data)
    print("Decrypted:", decrypted_data.decode())

if __name__ == "__main__":
    main()
