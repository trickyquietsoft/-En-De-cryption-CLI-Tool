import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Configuration
SALT_SIZE = 16
ITERATIONS = 600000 
KEY_LEN = 32         

def ReadData(address):
    if os.path.exists(address):
        with open(address, "rb") as f:
            return f.read()
    else:
        print("Error: File not found.")
        return None

def WriteData(address, data, extension=".ded"):
    if not address.endswith(extension) and extension != "":
        address = address + extension
    with open(address, "wb") as f:
        f.write(data)
    print(f"Success: Data written to {address}")

def DeriveKey(password, salt):
    """Helper function to derive key."""
    return PBKDF2(password, salt, dkLen=KEY_LEN, count=ITERKS, hmac_hash_module=SHA256)

# We use a global or passed constant for iterations to keep it clean
ITERKS = 600000 

def EncryptData(plaintext, salt, key):
    """
    Encrypts data using the provided salt and pre-derived key.
    Returns the full blob including salt, nonce, and tag.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # We MUST prepend the salt and nonce so the decrypter knows how to work
    return salt + cipher.nonce + tag + ciphertext

def DecryptData(encrypted_blob, password):
    """Decrypts data by extracting salt from the blob first."""
    try:
        # 1. Extract the salt from the start of the blob
        salt = encrypted_blob[:SALT_SIZE]
        
        # 2. Re-derive the key using the extracted salt and the user password
        key = PBKDF2(password, salt, dkLen=KEY_LEN, count=ITERKS, hmac_hash_module=SHA256)
        
        # 3. Extract the rest of the pieces
        nonce = encrypted_blob[SALT_SIZE : SALT_SIZE + 16]
        tag = encrypted_blob[SALT_SIZE + 16 : SALT_SIZE + 16 + 16]
        ciphertext = encrypted_blob[SALT_SIZE + 16 + 16:]
        
        # 4. Decrypt and Verify
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        return None

def EncryptionPrompt():
    print("\n--- AES-GCM Encryption Mode ---")
    readAddress = input("Input file path: ")
    password = input("Enter Password: ")
    
    data = ReadData(readAddress)
    if data is not None:
        # --- THE MOVED OPERATIONS ---
        print("Generating secure salt and deriving key...")
        salt = get_random_bytes(SALT_SIZE)
        
        
        # Re-implementing the key derivation directly for the prompt:
        key = PBKDF2(password, salt, dkLen=KEY_LEN, count=ITERKS, hmac_hash_module=SHA256)
        # ----------------------------

        writeAddress = input("Output file path: ")
        
        # Pass the prepared salt and key into the encryption function
        encrypted_blob = EncryptData(data, salt, key)
        
        WriteData(writeAddress, encrypted_blob)
        print("Operation Complete.")

def DecryptionPrompt():
    print("\n--- AES-GCM Decryption Mode ---")
    readAddress = input("Input file path: ")
    password = input("Enter Password: ")
    
    encrypted_blob = ReadData(readAddress)
    if encrypted_blob is not None:
        writeAddress = input("Output file path: ")
        decrypted_data = DecryptData(encrypted_blob, password)
        
        if decrypted_data is not None:
            WriteData(writeAddress, decrypted_data, extension="")
            print("Operation Complete.")
        else:
            print("Decryption Failed: Wrong password or file corruption.")

if __name__ == "__main__":
    print("Welcome to Secure AES-GCM CLI Tool")
    print("1. Encrypt\n2. Decrypt\n3. Exit")
    ans = input("-> ")

    if ans == '1':
        EncryptionPrompt()
    elif ans == '2':
        DecryptionPrompt()
    elif ans == '3':
        print("Goodbye")
