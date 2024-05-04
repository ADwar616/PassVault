from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Global variable to track failed login attempts
failed_attempts = 0

# Define stealth mode encryption key (example key, should be securely stored)
stealth_mode_key = b'StealthKey123456'

def pad_PKCS7(data, block_size):
    padding_size = block_size - (len(data) % block_size)
    padding = bytes([padding_size] * padding_size)
    return data + padding

def unpad_PKCS7(data):
    padding_size = data[-1]
    if padding_size > len(data) or padding_size == 0:
        return data
    for byte in data[-padding_size:]:
        if byte != padding_size:
            return data
    return data[:-padding_size]

def encrypt_AES(plaintext, key, block_size=16):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        padded_block = pad_PKCS7(block, block_size)
        encrypted_block = cipher.encrypt(padded_block)
        ciphertext += encrypted_block
    return ciphertext

def decrypt_AES(ciphertext, key, block_size=16):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b""
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        if len(block) < block_size:
            block = block + b'\x00' * (block_size - len(block))
        decrypted_block = cipher.decrypt(block)
        unpadded_block = unpad_PKCS7(decrypted_block)
        plaintext += unpadded_block
    return plaintext

def derive_key_from_password(password, salt=b'', key_length=16):
    global stealth_mode_key
    if len(password) < 16:
        print(f"Plaintext '{password}' is less than 16 bytes, appending stealth key.")
        password += stealth_mode_key
        
        print(f"New password for key derivation: {password}")
    else:
        print(f"Using plaintext '{password}' for key derivation.")

    derived_key = PBKDF2(password, salt, dkLen=key_length)
    valid_key_sizes = [16, 24, 32]  
    adjusted_key_length = min(valid_key_sizes, key=lambda x: abs(x - len(derived_key)))

    if adjusted_key_length != len(derived_key):
        if len(password) >= 16:
            padded_plaintext = pad_PKCS7(password, adjusted_key_length)
            print(f"Padding plaintext to {adjusted_key_length} bytes.")
            print(f"Padded plaintext: {padded_plaintext}")
            derived_key = PBKDF2(padded_plaintext, salt, dkLen=adjusted_key_length)
        else:
            print(f"Adjusting derived key length from {len(derived_key)} to {adjusted_key_length} bytes.")
            derived_key = derived_key[:adjusted_key_length]
            if len(derived_key) < adjusted_key_length:
                derived_key += get_random_bytes(adjusted_key_length - len(derived_key))

    print(f"Derived key: {derived_key.hex()}")
    return derived_key

def stealth_mode_encrypt_AES(plaintext):
    global stealth_mode_key
    return encrypt_AES(plaintext, stealth_mode_key)

def stealth_mode_decrypt_AES(ciphertext):
    global stealth_mode_key
    return decrypt_AES(ciphertext, stealth_mode_key)

def main():
    global failed_attempts
    plaintext = input("Enter the plaintext: ").encode()
    print(f"Plaintext: {plaintext}")

    # Determine the strength of the encryption key based on plaintext length
    key_length = 16 if len(plaintext) < 16 else len(plaintext)

    # Derive the encryption key using adaptive key strengthening
    key = derive_key_from_password(plaintext, key_length=key_length)
    print(f"Derived key: {key.hex()}")

    # Check if stealth mode encryption should be triggered
    if failed_attempts >= 5:
        ciphertext = stealth_mode_encrypt_AES(plaintext)
        print("Stealth Mode Encrypted:", ciphertext.hex())
    else:
        ciphertext = encrypt_AES(plaintext, key)
        print("Regular Encrypted:", ciphertext.hex())

    # Simulate decryption attempt (example)
    if failed_attempts >= 5:
        decrypted = stealth_mode_decrypt_AES(ciphertext)
        print("Stealth Mode Decrypted:", decrypted.decode())
    else:
        decrypted = decrypt_AES(ciphertext, key)
        print("Regular Decrypted:", decrypted.decode())

if __name__ == "__main__":
    main()

# if __name__ == "__main__":
#     main()
