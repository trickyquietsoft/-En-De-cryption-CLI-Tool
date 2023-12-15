from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import os


def ReadData(address):
    if os.path.exists(address):
        with open(address, "rb") as f:
            data = f.read()
        return data
    else:
        print("File not found.")
        return None


def EncryptData(fdata, cipher):
    padded_fdata = pad(fdata, AES.block_size)
    encrypted_data = cipher.encrypt(padded_fdata)
    return encrypted_data


def DecryptData(fdata, cipher):
    padded_decrypted_data = cipher.decrypt(fdata)
    decrypted_data = unpad(padded_decrypted_data, AES.block_size)
    return decrypted_data


def WriteEncryptedData(fdata, address):
    address = address + '.ded'
    with open(address, "wb") as f:
        f.write(fdata)


def WriteAnyData(fdata, address):
    with open(address, "wb") as f:
        f.write(fdata)


'''Prompt fucntions exist largly for testing purposes'''


def EncryptionPrompt():
    print("Cryptodome Encryption Test")
    readAddress = input("Input file address:")
    password = input("Key:")
    pwHash = SHA256.new(password.encode(encoding='utf-8')).digest()
    cipher = AES.new(pwHash, AES.MODE_ECB)
    data = ReadData(readAddress)

    if data is not None:
        writeAddress = input("Output file address:")
        encryptedData = EncryptData(pwHash + data, cipher)
        WriteEncryptedData(encryptedData, writeAddress)
        print("Operation Complete")
    else:
        print("Address not found.")
        EncryptionPrompt()


def DecryptionPrompt():
    print("Cryptodome Decryption Test")
    readAddress = input("Input file address:")
    password = input("Key:")
    pwHash = SHA256.new(password.encode(encoding='utf-8')).digest()
    cipher = AES.new(pwHash, AES.MODE_ECB)
    data = ReadData(readAddress)

    # Check the read data to make sure it worked
    if data is not None:
        writeAddress = input("Output file address:")
        decryptedData = DecryptData(data, cipher)
        # Extract the stored hash from the decrypted data
        # The number is based on the number of bytes in the hash
        storedHash = decryptedData[:32]
        # Remove the hash from the decrypted data
        finDecryptedData = decryptedData[32:]

        # Comparing hashes to check intergrity
        if pwHash == storedHash:
            WriteAnyData(finDecryptedData, writeAddress)
            print("Operation Complete")
        else:
            print("Hash mismatch.")
            DecryptionPrompt()
    else:
        DecryptionPrompt()


if __name__ == "__main__":

    ans = input(
        "Welcome to (En/De)cryption CLI Tool. \n 1. Encryption \n 2. Decryption" " \n 3. Exit \n->")

    if ans == '1':
        EncryptionPrompt()
    elif ans == '2':
        DecryptionPrompt()
    elif ans == '3':
        print("Goodbye")
        exit()
