import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Define constants
SALT_SIZE = 16  # 128 bits
KEY_SIZE = 32   # 256 bits
ITERATIONS = 100000  # Number of PBKDF2 iterations

def derive_key(master_password, salt):
    """
    Derive a cryptographic key from the master password and salt using PBKDF2.
    """
    pbkdf = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, ITERATIONS, dklen=KEY_SIZE)
    return pbkdf

def encrypt_password(password, key):
    """
    Encrypt the password using AES in CTR mode with the derived key.
    """
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_password(ciphertext, key):
    """
    Decrypt the password using AES in CTR mode with the derived key.
    """
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Example usage
master_password = "MySuperSecretMasterPassword"
salt = os.urandom(SALT_SIZE)
key = derive_key(master_password, salt)

password1 = "MyPassword1"
password2 = "MyPassword2"

encrypted_password1 = encrypt_password(password1, key)
encrypted_password2 = encrypt_password(password2, key)

decrypted_password1 = decrypt_password(encrypted_password1, key)
decrypted_password2 = decrypt_password(encrypted_password2, key)

print("Original Password 1:", password1)
print("Decrypted Password 1:", decrypted_password1)
print("Original Password 2:", password2)
print("Decrypted Password 2:", decrypted_password2)