import socket
import json
from cryptography.hazmat.primitives import hashes
import uuid
import threading
import time
class EDOIServer():
    def __init__(self,port,ip,edoi_port,edoi_ip,name) -> None:
        self.server_socket = None
        self.neighbors = {}
        self.port = port # This server's port
        self.ip = ip #This server's IP
        self.name = name # This server's name
        #EDOI server's port and IP
        self.edoi_port = edoi_port
        self.edoi_ip = edoi_ip
        self._send_connect()
        time.sleep(0.5)
        threading.Thread(target=self.start_server, daemon=True).start()
        while True:
            time.sleep(0.05)
    def _send_connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((self.edoi_ip, self.edoi_port))
            print(f"[+] Connected to EDOI node at {self.edoi_ip}:{self.edoi_port}")

            # Send a message to the EDOI node
            message = json.dumps({"type": "connect","tup":(self.ip,self.port)}).encode('utf-8')
            client_socket.sendall(message)
            
            print("[√] Message sent successfully.")
    def compute_hashed_identity(self,name:str, salt: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    def _handle_conn(self,data):
        # print(data)
        if(data.get("type") == "find"):
            route = data.get("route", None)
            target_hash = data.get("hash", None)
            if route and target_hash:
                salt = data.get("salt", None)
                name_hash = self.compute_hashed_identity(self.name, salt)
                if name_hash == target_hash:
                    route_member = {"hash":name_hash,"salt":salt}
                    route.append(route_member)
                    ret_data = {"type":"path","route":route,"count":len(route)-2,"hash":target_hash,"salt":salt}
                    ret_data["message_id"] = str(uuid.uuid4())
                    try:
                        json_str = json.dumps(ret_data)
                        encoded = json_str.encode('utf-8')

                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                            client_socket.connect((self.edoi_ip, self.edoi_port))
                            client_socket.sendall(encoded)
                    except Exception as e:
                        print(f"[!] Error sending data: {e}")
        elif(data.get("type") == "connect"):
            pass
        elif(data.get("type") == "return"):
            print("data:",data)
        elif(data.get("type") == "forward"):
            # print(data.keys())
            count = data.get("count",None)
            route = data.get("route",None)
            end_point = route[count]
            salt = route[count]["salt"]

            end_hash = end_point.get("hash",None)
            my_hash = self.compute_hashed_identity(self.name,salt)
            if(my_hash == end_hash):
                payload = data.get("payload",None)
                print(payload)

                
            # pass
    def start_server(self):
         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', int(self.port)))
            server_socket.listen()
            print(f"[+] Listening forever on port {self.port}...")

            while True:
                conn, addr = server_socket.accept()
                with conn:
                    # print(f"[+] Connection from {addr}")

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
                        self._handle_conn(json_data)
                        
                        # print(f"[√] Received JSON: {json_data}")
                    except json.JSONDecodeError as e:
                        print(f"[!]JSON decode error: {e}")
                    except Exception as e:
                        print(f"[!]General error: {e}")
                    finally:
                        pass
                        # print("[*] Connection closed.\n")

node = EDOIServer(5400,'127.0.0.1',5199,'127.0.0.1',"TestNode")