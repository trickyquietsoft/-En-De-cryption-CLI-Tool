AES-GCM File Encryption Tool
A lightweight, high-security Command Line Interface (CLI) tool for encrypting and decrypting files using industry-standard cryptographic primitives.

🛡️ Security Architecture
This tool does not use basic encryption; it uses Authenticated Encryption with Associated Data (AEAD) to ensure your files are both private and untampered with.

Algorithm: AES-256-GCM (Galois/Counter Mode).
Key Derivation: PBKDF2 with HMAC-SHA256.
Brute-Force Protection: 600000 iterations of hashing to make password guessing computationally expensive.
Integrity Check: Uses an authentication Tag to detect if even a single bit of the encrypted file has been modified.
Salted Hashing: A unique 16-byte random salt is generated for every encryption, preventing rainbow table attacks.
🚀 Getting Started
Prerequisites
You must have Python 3.x installed on your system.

Installation
Clone or download this repository.
Install the required dependency using pip:
pip install pycryptodome
📖 How to Use
Run the program using the following command:

python main.py
1. Encrypting a File
Select Option 1 from the menu.
Input file path: Enter the path to the file you want to protect (e.g., my_secrets.txt).
Enter Password: Type a strong password. Note: Do not lose this password!
Output file path: Enter the name for the new encrypted file (e.g., my_secrets.ded).
2. Decrypting a File
Select Option 2 from the menu.
Input file path: Enter the path to your .ded file.
Enter Password: Type the exact password used during encryption.
Output file path: Enter the name for the restored file (e.g., restored_file.txt).
⚠️ Warning: Password Loss
This tool provides no "Password Recovery" feature. The security of your data relies entirely on the strength of your password. If you forget the password used to encrypt a file, the data is permanently unrecoverable.

