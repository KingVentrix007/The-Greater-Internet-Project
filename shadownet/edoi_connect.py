import time
import socket
import threading
import os
import json
from cryptography.hazmat.primitives import hashes
import uuid
global_port = 0
def listen_for_message():

    # Listens for incoming messages on the specified port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', int(global_port)))
            server_socket.listen()
            print(f"[+] Listening forever on port {global_port}...")

            while True:
                conn, addr = server_socket.accept()
                with conn:
                    print(f"[+] Connection from {addr}")

                    data_chunks = []
                    while True:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break  # Connection closed by client
                        data_chunks.append(chunk)

                    full_data = b''.join(data_chunks)
                    try:
                        decoded = full_data.decode('utf-8')
                        # print(f"[>] Full raw data: {decoded}")

                        json_data = json.loads(decoded)
                        # print(f"[√] Received JSON: {json_data}")
                        # in_ip,in_port = addr
                        # neighbors[addr] = None
                        # handle_conn(json_data,addr,conn)
                        print(f"[√] Received JSON: {json_data}")
                    except json.JSONDecodeError as e:
                        print(f"[!]JSON decode error: {e}")
                    except Exception as e:
                        print(f"[!]General error: {e}")
                    finally:
                        # pass
                        print("[*] Connection closed.\n")


def compute_hashed_identity(name:str, salt: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()

def init_connect(ip,port,client_port):
     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((ip, port))
            print(f"[+] Connected to EDOI node at {ip}:{port}")

            # Send a message to the EDOI node
            message = json.dumps({"type": "connect","tup":(ip,client_port)}).encode('utf-8')
            client_socket.sendall(message)
            
            print("[√] Message sent successfully.")

def do_request(client_hash,secure_salt,client_port,target_hash,ip,port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((ip, port))
            route_member = {"hash": client_hash, "salt": secure_salt}
            route = [route_member]
            packet = {
            "type": "find",
            "route": route,
            "hash": target_hash,
            "salt": secure_salt,
            # "key": self.public_key.public_bytes(
            #     encoding=serialization.Encoding.PEM,
            #     format=serialization.PublicFormat.SubjectPublicKeyInfo
            # ).decode(),
            
            "message_id": str(uuid.uuid4()),
            "my_ip":('127.0.0.1',client_port)
        }
            client_socket.sendall(json.dumps(packet).encode())

def connect_to_edoi():
    ip = input("Enter the EDOI IP address: ")
    port = input("Enter the EDOI port: ")
    client_name = input("Enter your client name: ")
    client_port = input("Enter the port to listen for messages (default 5000): ") or "5000"
    secure_salt = os.urandom(16).hex()  # Generate a secure random salt
    client_hash = compute_hashed_identity(client_name, secure_salt)
    target = input("Enter the target node to search for: ")
    target_hash = compute_hashed_identity(target,secure_salt)
    try:
        # Validate IP address
        port = int(port)
        if not (0 <= port <= 65535):
            raise ValueError("Port must be between 0 and 65535.")
        # Setup threaded listening server
        global global_port
        global_port = int(client_port)
        threading.Thread(target=listen_for_message, daemon=True).start()
        print(f"[+] Listening for messages on port {port}...")
        # Connect to EDOI node
        init_connect(ip,port,client_port=int(client_port))
        time.sleep(2)
        do_request(client_hash,secure_salt,int(client_port),target_hash,"127.0.0.1",port)     
        while(True):
             time.sleep(1)       
    except Exception as e:
        print(e)

connect_to_edoi()
