import socket
import json
import base64
from Include import SerializeKey as SerializeKey
from Include import CPABE as cp_abe
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import bytesToObject

def main():
    HOST = '127.0.0.1'  # Server's address
    PORT = 12345

    # Prepare the credentials JSON to send.
    credentials = {
        "staff": {
            "1": {
                "Faculty": "Computer Science",
                "ID": "BS001",
                "PASS": "131244e139d73677d1ad39c5cf0847801e2908b93df0eca1353c22167932e31a",
                "UserName": "placement_coordinator@university.edu"
            },
            "2": {
                "Faculty": "Information Technology",
                "ID": "BS002",
                "PASS": "7d302c9c692a7376d32214b485d7046fc5cf725453c783e10a572bfdb3523b29",
                "UserName": "it_coordinator@university.edu"
            }
        }
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(json.dumps(credentials).encode())
        # Receive the public key (Base64 encoded)
        pk_b64 = s.recv(4096)
        if not pk_b64:
            print("No public key received from server.")
            return
        pk_str = pk_b64.decode()
        try:
            # Decode the Base64 string to bytes, then deserialize using bytesToObject.
            group = PairingGroup('MNT224')
            pk_obj = bytesToObject(base64.b64decode(pk_str), group)
        except Exception as e:
            print("Failed to load public key:", e)
            return
        print("Public key received:", pk_obj)

if __name__ == '__main__':
    main()
