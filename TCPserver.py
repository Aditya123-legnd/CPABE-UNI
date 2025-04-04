import socket
import json
import base64
from Include import SerializeKey as SerializeKey
from Include import CPABE as cp_abe
from charm.toolbox.pairinggroup import PairingGroup, G1, GT  # Import the pairing group types

def main():
    host = 'localhost'
    port = 62345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")
    
    # Initialize the SerializeKey instance (it probably has its own group internally)
    key = SerializeKey.serializeKey()
    
    # Create a pairing group instance for generating valid dummy elements.
    group = PairingGroup('SS512')
    
    while True:
        client_socket, addr = server_socket.accept()
        print("Accepted connection from:", addr)
        data = client_socket.recv(1024)
        if not data:
            client_socket.close()
            continue
        
        try:
            json_data = json.loads(data.decode('utf-8'))
        except json.JSONDecodeError:
            print("Error decoding JSON from client.")
            client_socket.close()
            continue
        
        print("Received JSON data:", json_data)
        
        # Create dummy CP-ABE keys using valid group elements:
        pk = {
            "g": group.random(G1),                 # Valid group element from G1
            "h_A": [group.random(G1)],               # h_A should be a list of valid elements
            "e_g_g_alpha": group.random(GT)          # Valid group element from GT
        }
        sk = {
            "D": group.random(G1),                   # Dummy secret key element
            "Dj": [group.random(G1)]                 # List of dummy elements
        }
        
        try:
            pk_serialized = key.jsonify_pk(pk)  # Now should work because elements are valid
            sk_serialized = key.jsonify_sk(sk)
        except Exception as e:
            print("Error serializing keys:", e)
            client_socket.close()
            continue
        
        # Base64-encode the serialized keys.
        pk_b64 = base64.b64encode(pk_serialized).decode('utf-8')
        sk_b64 = base64.b64encode(sk_serialized).decode('utf-8')
        
        # Pad the public key string to exactly 880 characters.
        pk_b64_padded = pk_b64.ljust(880)
        response = pk_b64_padded + sk_b64
        
        client_socket.sendall(response.encode('utf-8'))
        client_socket.close()

if __name__ == '__main__':
    main()
