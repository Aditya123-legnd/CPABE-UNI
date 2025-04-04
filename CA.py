from charm.toolbox.pairinggroup import PairingGroup,ZR, G1, G2, GT
from charm.core.engine.util import *
from charm.schemes.abenc.ac17 import AC17CPABE
from charm.toolbox.msp import MSP
from Include import AC17Serialize as AC17Serialize
from Include import CPABE as cp_abe
from Include import SerializeKey as SerializeKey
from Crypto.Util.number import bytes_to_long,long_to_bytes
import json
import socket
import pickle
import base64


def main():
    HOST = ''  # Listen on all available interfaces
    PORT = 12345

    # Server-side "database" of valid staff credentials
    server_data = {
        "BS001": {
            "Faculty": "Computer Science",
            "PASS": "131244e139d73677d1ad39c5cf0847801e2908b93df0eca1353c22167932e31a",
            "UserName": "placement_coordinator@university.edu"
        },
        "BS002": {
            "Faculty": "Information Technology",
            "PASS": "7d302c9c692a7376d32214b485d7046fc5cf725453c783e10a572bfdb3523b29",
            "UserName": "it_coordinator@university.edu"
        }
    }

    # Initialize CP-ABE scheme and generate public key and master secret key.
    group = PairingGroup('MNT224')
    cpabe = AC17CPABE(group, 2)
    pk, msk = cpabe.setup()

    # Serialize the public key using objectToBytes, then encode as Base64 string.
    pk_bytes = objectToBytes(pk, group)
    pk_b64 = base64.b64encode(pk_bytes).decode('utf-8')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print("Server is listening...")
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)
            data = conn.recv(4096)
            print("Received data")
            try:
                json_data = json.loads(data.decode())
            except Exception as e:
                print("JSON decode error:", e)
                conn.sendall(b"")
                return

            # Expecting a structure like: {"staff": { "1": { ... }, "2": { ... } } }
            staff = json_data.get("staff", {})
            valid = False
            # Iterate over each staff record and validate credentials.
            for key, record in staff.items():
                staff_id = record.get("ID")
                faculty = record.get("Faculty")
                if staff_id in server_data:
                    if faculty and faculty.lower() == server_data[staff_id]["Faculty"].lower():
                        valid = True
                        break
            if valid:
                print("Credentials validated.")
                # Send the Base64-encoded public key string to the client.
                conn.sendall(pk_b64.encode())
            else:
                print("Invalid credentials.")
                conn.sendall(b"")

if __name__ == '__main__':
    main()
