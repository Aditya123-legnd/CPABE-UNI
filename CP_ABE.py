import json
import os
import time
from charm.toolbox.pairinggroup import PairingGroup, GT, G1
from charm.core.math.pairing import hashPair as sha2
from charm.schemes.abenc.ac17 import AC17CPABE
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes

# =======================
# Test File Generation
# =======================
def create_test_file(file_path, size_kb, num_attributes):
    """
    Create a test JSON file with the specified size (in kilobytes) and a variable number 
    of attributes for placement coordinators, internships, training programs, and events.
    This version uses a fixed encryption policy suitable for CP-ABE.
    """
    # Fixed encryption policy for CP-ABE
    policy_str = "BN001 and BS001"
    
    # Base data structure for the test file
    data = {
        "StudentID": "BN001",
        "StudentName": "Andrew N",
        "DateOfBirth": "01/01/2003",
        "Gender": "Male",
        "Major": "Computer Science",
        "CGPA": 8.5,
        "CreditsEarned": 120,
        "PlacementCoordinators": [
            {"CoordinatorID": f"BS00{i}", "Role": f"P✅ 📊 LaTeX Code for Experimental Results with Tables latex Copy Edit Placement Coordinator {i}"}
            for i in range(1, num_attributes + 1)
        ],
        "InternshipHistory": [
            {"year": f"202{i}", "description": f"Internship {i}"}
            for i in range(1, num_attributes + 1)
        ],
        "TrainingPrograms": [
            {
                "program_name": f"Training Program {i}",
                "duration": f"{i} weeks",
                "frequency": "Daily sessions",
                "start_date": f"2022-01-{i:02d}",
                "end_date": f"2022-01-{i + 7:02d}"
            }
            for i in range(1, num_attributes + 1)
        ],
        "PlacementEvents": [
            {
                "event_name": f"Placement Event {i}",
                "event_date": f"2022-01-{i:02d}",
                "event_duration": "1 day",
                "event_location": f"Location {i}"
            }
            for i in range(1, num_attributes + 1)
        ],
        "ContactInformation": {
            "Address": "123 University Ave, Campus Town",
            "MobileNumber": "09xxxxxxxxxx",
            "Email": "xyz@gmail.com"
        },
        "EncryptionPolicy": {
            "Policy": policy_str,
            "DATA": "This is encrypted student record data..."
        }
    }
    
    # Calculate current JSON data size in bytes
    current_size = len(json.dumps(data).encode('utf-8'))
    target_size = size_kb * 1024
    
    # Append filler data to approximately reach the target file size
    if current_size < target_size:
        filler_size = target_size - current_size
        data["EncryptionPolicy"]["DATA"] = "A" * filler_size
    else:
        data["EncryptionPolicy"]["DATA"] = "A" * max(0, target_size - 1000)  # fallback adjustment
    
    # Write the JSON data to file
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def generate_test_files():
    """
    Generate test files with various sizes (in KB) and numbers of attributes.
    This function creates a 'test_files' directory and generates files if they do not already exist.
    Returns a list of file paths for the generated test files.
    """
    sizes_kb = [1] # File sizes in KB #[10, 100, 1000,10000, 100000, 3, 30, 300, 3000, 30000, 300000, 5, 50, 500, 5000, 50000, 500000] #Due to github limit another example sizes are in list 
    num_attributes_list = [1] # Number of attributes #[3, 5] #Due to github limit another example no. of attributes are in list        

    os.makedirs("test_files", exist_ok=True)
    generated_files = []
    for size_kb in sizes_kb:
        for num_attributes in num_attributes_list:
            file_name = f"test_{size_kb}KB_{num_attributes}attr.json"
            file_path = os.path.join("test_files", file_name)
            # Generate the file if it doesn't exist already.
            if not os.path.exists(file_path):
                create_test_file(file_path, size_kb, num_attributes)
                print(f"Created {file_path}")
            generated_files.append(file_path)
    return generated_files

# =======================
# CP-ABE with Blowfish Integration
# =======================
# Padding functions for Blowfish (block size: 8 bytes)
def pad(data):
    bs = Blowfish.block_size
    plen = bs - (len(data) % bs)
    return data + bytes([plen]) * plen

def unpad(data):
    plen = data[-1]
    return data[:-plen]

# ...remaining code unchanged...

class AC17CPABE_:
    def __init__(self):
        self.group = PairingGroup('MNT224')
        self.cpabe = AC17CPABE(self.group, 2)
        
    def gen_key(self):
        # Generate public key and master secret key
        pk, msk = self.cpabe.setup()
        return pk, msk
    
    def gen_sk(self, pk, msk, attr_list):
        # Generate secret key for a given attribute list
        sk = self.cpabe.keygen(pk, msk, attr_list)
        return sk
    
    def encryption(self, pk, policy_str, msg):
        # Generate a random pairing group element as the symmetric key
        key = self.group.random(GT)
        # Encrypt the key using CP-ABE under the given policy
        c1 = self.cpabe.encrypt(pk, key, policy_str)
        
        # Derive a 16-byte key for Blowfish from the pairing key using sha2
        bf_key = sha2(key)[:16]
        # Generate a random IV for Blowfish in CBC mode
        iv = get_random_bytes(Blowfish.block_size)
        cipher_bf = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv)
        padded_msg = pad(msg)
        c2 = cipher_bf.encrypt(padded_msg)
        
        result = {
            "c1": c1,
            "c2": c2,
            "iv": iv
        }
        return result
    
    def decryption(self, pk, sk, cipher):
        c1 = cipher["c1"]
        c2 = cipher["c2"]
        iv = cipher["iv"]
        try:
            # Recover the pairing key using the secret key
            key1 = self.cpabe.decrypt(pk, c1, sk)
            bf_key = sha2(key1)[:16]
            cipher_bf = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv)
            padded_msg = cipher_bf.decrypt(c2)
            rec_msg = unpad(padded_msg)
            return rec_msg
        except Exception as e:
            print("Decryption failed:", e)
            return None
        
    def verify_msg(self, msg, rec_msg):
        if rec_msg == msg:
            print("Successful decryption.")
        else:
            print("Decryption failed.")

# =======================
# Main Integration: Process Each Test File
# =======================
def process_test_file(file_path):
    """
    Read a test file, perform CP-ABE key generation, encryption, and decryption,
    and then print the performance metrics for the given file.
    """
    print(f"\nProcessing file: {file_path}")
    # Read file content
    with open(file_path, 'rb') as sourcefile:
        msg = sourcefile.read()
    try:
        msg_dict = json.loads(msg)
    except Exception as e:
        print("Failed to parse JSON:", e)
        return

    # File metrics
    file_size = len(msg)  # in bytes
    # To satisfy the policy "BN001 and BS001", we include both attributes.
    attr_list = [msg_dict.get("StudentID", "Unknown"), "BS001"]
    num_attributes = len(attr_list)

    abe = AC17CPABE_()

    # Measure key generation time
    start_time = time.perf_counter()
    pk, msk = abe.gen_key()
    keygen_time = time.perf_counter() - start_time

    # Generate secret key
    sk = abe.gen_sk(pk, msk, attr_list)

    # Get encryption policy from file, or use default
    policy = msg_dict.get("EncryptionPolicy", {}).get("Policy", "BN001 and BS001")
    
    # Measure encryption time
    start_time = time.perf_counter()
    cipher = abe.encryption(pk, policy, msg)
    encryption_time = time.perf_counter() - start_time
    
    # Measure decryption time
    start_time = time.perf_counter()
    re_msg = abe.decryption(pk, sk, cipher)
    decryption_time = time.perf_counter() - start_time
    
    # Verify decryption result
    abe.verify_msg(msg, re_msg)
    
    # Print metrics for this file
    print("Performance Metrics for this file:")
    print("  File Size (bytes):", file_size)
    print("  Number of Attributes in SK:", num_attributes)
    print("  Key Generation Time: {:.6f} seconds".format(keygen_time))
    print("  Encryption Time: {:.6f} seconds".format(encryption_time))
    print("  Decryption Time: {:.6f} seconds".format(decryption_time))

def main():
    # Generate test files (if not already generated)
    test_files = generate_test_files()
    
    # Process each generated test file
    for file_path in test_files:
        process_test_file(file_path)

if __name__ == '__main__':
    main()
