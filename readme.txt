# Create test files
mkdir test_files
touch test_files/file{1..5}.txt
echo "Test content" > test_files/document.txt

# Run encryption
python3 ransomware_sim.py

# Run decryption
python3 ransomware_sim.py
# Enter key when prompted: Abhishek!234@#$
