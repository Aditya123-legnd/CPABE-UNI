#Modified CPABE to integrate Blowfish encryption for images / Video file processing .
import json
import os
import time
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.core.math.pairing import hashPair as sha2
from charm.schemes.abenc.ac17 import AC17CPABE
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes

# =======================
# Utility Functions
# =======================
def pad(data):
    bs = Blowfish.block_size
    plen = bs - (len(data) % bs)
    return data + bytes([plen]) * plen

def unpad(data):
    plen = data[-1]
    return data[:-plen]

# =======================
# CP-ABE with Blowfish Integration
# =======================
class AC17CPABE_:
    def __init__(self):
        self.group = PairingGroup('MNT224')
        self.cpabe = AC17CPABE(self.group, 2)
        
    def gen_key(self):
        pk, msk = self.cpabe.setup()
        return pk, msk
    
    def gen_sk(self, pk, msk, attr_list):
        sk = self.cpabe.keygen(pk, msk, attr_list)
        return sk
    
    def encryption(self, pk, policy_str, msg):
        key = self.group.random(GT)
        c1 = self.cpabe.encrypt(pk, key, policy_str)
        bf_key = sha2(key)[:16]
        iv = get_random_bytes(Blowfish.block_size)
        cipher_bf = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv)
        padded_msg = pad(msg)
        c2 = cipher_bf.encrypt(padded_msg)
        return {"c1": c1, "c2": c2, "iv": iv}
    
    def decryption(self, pk, sk, cipher):
        c1 = cipher["c1"]
        c2 = cipher["c2"]
        iv = cipher["iv"]
        try:
            key1 = self.cpabe.decrypt(pk, c1, sk)
            bf_key = sha2(key1)[:16]
            cipher_bf = Blowfish.new(bf_key, Blowfish.MODE_CBC, iv)
            padded_msg = cipher_bf.decrypt(c2)
            return unpad(padded_msg)
        except Exception as e:
            print("Decryption failed:", e)
            return None
        
    def verify_msg(self, msg, rec_msg):
        if rec_msg == msg:
            print("Successful decryption.")
        else:
            print("Decryption failed.")

# =======================
# Process a Single File
# =======================
def process_file(file_path):
    """
    Perform CP-ABE key generation, encryption, and decryption on a single file.
    """
    print(f"\nProcessing file: {file_path}")
    with open(file_path, 'rb') as sourcefile:
        msg = sourcefile.read()

    file_size = len(msg)
    attr_list = ["BN001", "BS001"]  # Example attributes
    num_attributes = len(attr_list)

    abe = AC17CPABE_()
    start_time = time.perf_counter()
    pk, msk = abe.gen_key()
    keygen_time = time.perf_counter() - start_time

    sk = abe.gen_sk(pk, msk, attr_list)
    policy = "BN001 and BS001"  # Example policy
    
    start_time = time.perf_counter()
    cipher = abe.encryption(pk, policy, msg)
    encryption_time = time.perf_counter() - start_time
    
    start_time = time.perf_counter()
    re_msg = abe.decryption(pk, sk, cipher)
    decryption_time = time.perf_counter() - start_time
    
    abe.verify_msg(msg, re_msg)
    print("Performance Metrics for this file:")
    print("  File Size (bytes):", file_size)
    print("  Number of Attributes in SK:", num_attributes)
    print("  Key Generation Time: {:.6f} seconds".format(keygen_time))
    print("  Encryption Time: {:.6f} seconds".format(encryption_time))
    print("  Decryption Time: {:.6f} seconds".format(decryption_time))

# =======================
# Main Function
# =======================
def main():
    file_path = input("Enter the path to the file you want to process: ").strip()
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return
    process_file(file_path)

if __name__ == '__main__':
    main()