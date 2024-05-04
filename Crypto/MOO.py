from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Global variable to track failed login attempts
failed_attempts = 0

# Define stealth mode encryption key (example key, should be securely stored)
stealth_mode_key = b'StealthKey123456'

def encrypt_AES_GCM(plaintext, key, associated_data=None):
    cipher = AES.new(key, AES.MODE_GCM)
    if associated_data is not None:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    return ciphertext, tag, nonce

def decrypt_AES_GCM(ciphertext, key, nonce, tag, associated_data=None):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if associated_data is not None:
        cipher.update(associated_data)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        print("Authentication failed!")
        return b''

def encrypt_AES_CBC(plaintext, key, iv=None):
    if iv is None:
        iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, iv

def decrypt_AES_CBC(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def encrypt_AES_ECB(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt_AES_ECB(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def derive_key_from_password(password, salt=b'', key_length=16):
    return PBKDF2(password, salt, dkLen=key_length)

def stealth_mode_encrypt_AES(plaintext):
    global stealth_mode_key
    return encrypt_AES_GCM(plaintext, stealth_mode_key)

def stealth_mode_decrypt_AES(ciphertext, nonce, tag):
    global stealth_mode_key
    return decrypt_AES_GCM(ciphertext, stealth_mode_key, nonce, tag)

def main():
    global failed_attempts
    plaintext = input("Enter the plaintext: ").encode()

    # Determine the strength of the encryption key based on plaintext length
    key_length = 16 if len(plaintext) < 16 else len(plaintext)

    # Derive the encryption key using adaptive key strengthening
    key = derive_key_from_password(plaintext, key_length=key_length)

    # Check if stealth mode encryption should be triggered
    if failed_attempts >= 5:
        ciphertext, tag, nonce = stealth_mode_encrypt_AES(plaintext)
        print("Stealth Mode Encrypted (GCM):", ciphertext.hex(), tag.hex(), nonce.hex())
    else:
        # Encrypt using different modes
        ciphertext_gcm, tag, nonce = encrypt_AES_GCM(plaintext, key)
        print("GCM Encrypted:", ciphertext_gcm.hex(), tag.hex(), nonce.hex())

        ciphertext_cbc, iv = encrypt_AES_CBC(plaintext, key)
        print("CBC Encrypted:", ciphertext_cbc.hex(), iv.hex())

        ciphertext_ecb = encrypt_AES_ECB(plaintext, key)
        print("ECB Encrypted:", ciphertext_ecb.hex())

    # Simulate decryption attempt (example)
    if failed_attempts >= 5:
        decrypted = stealth_mode_decrypt_AES(ciphertext, nonce, tag)
        print("Stealth Mode Decrypted (GCM):", decrypted.decode())
    else:
        # Decrypt using different modes
        decrypted_gcm = decrypt_AES_GCM(ciphertext_gcm, key, nonce, tag)
        print("GCM Decrypted:", decrypted_gcm.decode())

        decrypted_cbc = decrypt_AES_CBC(ciphertext_cbc, key, iv)
        print("CBC Decrypted:", decrypted_cbc.decode())

        decrypted_ecb = decrypt_AES_ECB(ciphertext_ecb, key)
        print("ECB Decrypted:", decrypted_ecb.decode())

if __name__ == "__main__":
    main()