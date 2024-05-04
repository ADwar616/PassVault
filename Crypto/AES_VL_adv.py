from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

def encrypt_AES(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt_AES(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def derive_key(password, salt, iterations=100000):
    return PBKDF2(password, salt, dkLen=16, count=iterations)

def main():
    password = input("Enter a password: ").encode()
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    iv = get_random_bytes(16)

    plaintext = input("Enter the plaintext: ").encode()
    ciphertext = encrypt_AES(plaintext, key, iv)
    print("Encrypted:", ciphertext.hex())

    decrypted = decrypt_AES(ciphertext, key, iv)
    print("Decrypted:", decrypted.decode())

if __name__ == "__main__":
    main()