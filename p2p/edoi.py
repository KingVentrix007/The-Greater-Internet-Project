from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import threading
import random
import uuid
from typing import List, Optional, Set
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import socket
import json
import time
from collections import deque
import uuid
# --- Node Definition ---
class Node:
    def __init__(self, name: str):
        self.name = name
        self.id = uuid.uuid4().hex
        self._generate_keys()
        self.neighbors: List['Node'] = []
        

    def _generate_keys(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def encrypt(self, data: bytes) -> bytes:
        return hybrid_encrypt(data, self.public_key)

    def decrypt(self, data: bytes) -> Optional[bytes]:
        return hybrid_decrypt(data, self.private_key)

    
    def compute_hashed_identity(self, salt: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update((self.name + salt).encode())
        return digest.finalize().hex()

    def __repr__(self):
        return self.name

# ! Use this to add neighbors to each node during creation

class NetNode():
    def __init__(self, name: str,port,bootstrap_ips:list):
        self.name = name
        self.id = uuid.uuid4().hex
        self._generate_keys()
        self.neighbors = {}
        for ip in bootstrap_ips:
            self.neighbors[ip] = None
        self.port = port
        self.max_neighbors = 5
        self.seen_messages = set()

    def _generate_keys(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def encrypt(self, data: bytes) -> bytes:
        return hybrid_encrypt(data, self.public_key)

    def decrypt(self, data: bytes) -> Optional[bytes]:
        return hybrid_decrypt(data, self.private_key)

    
    def compute_hashed_identity(self, salt: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update((self.name + salt).encode())
        return digest.finalize().hex()
    
    def build_network(self):
        if(len(self.neighbors) < self.max_neighbors):
            # Will handle finding more neighbors
            pass
        for ip, key in self.neighbors.items():
            if key is None:
                # Simulate requesting a public key from the neighbor
                # print(f"Requesting public key from {ip}...")
                
                # This part will request a key from that server
                fake_key = None
                
                # Store the received key
                self.neighbors[ip] = fake_key
                # print(f"Received and stored key from {ip}: {fake_key}")
            
    
        pass # Will send RSA public key
    def send_data(self,data,addr):
        host, port = addr  # Unpack the address tuple
        try:
            json_str = json.dumps(data)
            encoded = json_str.encode('utf-8')

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                client_socket.sendall(encoded)
            time.sleep(0.05)
                # print(f"[√] Sent JSON to {host}:{port}")
        except Exception as e:
            pass
            # print(f"[!] Error sending JSON to {host}:{port} - {e}")
    def temp(self):
        route = []
        route_member = {"node_hash":"the nodes named, hashed ","salt":"the salt used to hash the name"}
        ## Packet:
        packet_find = {"type":"find","route":route,"hash":"the hash to find","key":"the last nodes RSA key(this nodes rsa if it is sending it)"}
    def continue_find(self,route,hash_to_find,debug_route=None,target=None,salt=None):
        packet = {"type":"find","route":route,"hash":hash_to_find,"debug_route":debug_route,"hash":target,"salt":salt, "message_id": str(uuid.uuid4())}
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        for ip, key in self.neighbors.items():
            # will later handle key encryption
            self.send_data(packet,ip)

    def return_path(self,path):
        message_id = path.get("message_id",None)
        path["message_id"] = message_id or str(uuid.uuid4())
        for ip, key in self.neighbors.items():
            self.send_data(path,ip)
    def hash_str(self,name,salt):
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    def start_find(self, target_name: str, salt: str):
        target_hash = self.hash_str(target_name, salt)  # FIXED
        my_hash = self.compute_hashed_identity(salt)
        route_member = {"hash": my_hash, "salt": salt}
        route = [route_member]
        debug_route_member = {"name":self.name,"len_route":len(route)}
        route = [route_member]
        debug_route = [debug_route_member]

        packet = {
            "type": "find",
            "route": route,
            "hash": target_hash,
            "salt": salt,
            # "key": self.public_key.public_bytes(
            #     encoding=serialization.Encoding.PEM,
            #     format=serialization.PublicFormat.SubjectPublicKeyInfo
            # ).decode(),
            "debug_route":debug_route,
            "message_id": str(uuid.uuid4())
        }
        for ip, key in self.neighbors.items():
            # will later handle key encryption
            self.send_data(packet,ip)
        # self.continue_find(route, target_hash)
    def return_to_sender(self, route, payload):
        count = len(route) - 1
        packet = {
            "type": "return",
            "route": route,
            "count": count,
            "payload": payload
        }
        # Send to previous hop
        for ip, _ in self.neighbors.items():
            self.send_data(packet, ip)
    def send_to_target(self, route, payload):
        count = len(route)-1
        packet = {
            "type": "forward",
            "route": route,
            "count": count,
            "payload": payload
        }
        # Send to next hop
        next_hop = route[count]["hash"]
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        for ip, _ in self.neighbors.items():
            self.send_data(packet, ip)

    def handle_conn(self,data,addr):
        message_id = data.get("message_id")
        if message_id and message_id in self.seen_messages:
            return  # Drop duplicate
        if(not message_id):
            print("U missed one")
        # Otherwise:
        if message_id:
            self.seen_messages.add(message_id)
        if(data["type"] == "get_rsa"):
            key = self.public_key
            key_data = {"key",key}
            self.send_data(key_data, addr)
        elif data['type'] == "return":
            try:
                route = data["route"]
                count = int(data["count"])
                payload = data["payload"]
                my_hash = self.compute_hashed_identity(route[count]["salt"])

                if my_hash == route[count]["hash"]:
                    if count > 0:
                        next_packet = {
                            "type": "return",
                            "route": route,
                            "count": count - 1,
                            "payload": payload
                        }
                        for ip, _ in self.neighbors.items():
                            self.send_data(next_packet, ip)
                    else:
                        print(f"[⬅️] Final ACK received at {self.name}: {payload}")
            except Exception as e:
                print(f"[!] Return error: {e}")
        elif data['type'] == "forward":
            try:
                route = data["route"]
                count = int(data["count"])
                payload = data["payload"]
                my_hash = self.compute_hashed_identity(route[count]["salt"])

                if self.compute_hashed_identity(route[count]["salt"]) == route[count]["hash"]:
                    if count + 1 < len(route):
                        next_packet = {
                            "type": "forward",
                            "route": route,
                            "count": count + 1,
                            "payload": payload
                        }
                        for ip, _ in self.neighbors.items():
                            self.send_data(next_packet, ip)
                    else:
                        print(f"[🎯] {self.name} received payload: {payload}")
                        self.return_to_sender(route, f"ACK from {self.name}")
            except Exception as e:
                print(f"[!] Forward error: {e}")

        elif data["type"] == "path":
            try:
                print(f"{self.name}: PATH received")
                route = data['route']
                count = int(data["count"])
                debug_route = data["debug_route"]

                my_member = route[count]
                my_hash = self.compute_hashed_identity(my_member["salt"])
                my_member_deb = debug_route[count]
                print(f"Name:{self.name}:{my_member_deb["name"]}")
                if(self.name == my_member_deb['name']):
                    print("Match")
                    if my_hash == my_member["hash"]:
                        print("Hash work")
                    else:
                        print("Hash not work")
                if my_hash == my_member["hash"]:
                    print(f"{self.name}: Stepping back: {count}")
                    if count > 0:
                        data['count'] = count - 1
                        self.return_path(data)
                    else:
                        print(f"{self.name}: Back at main")
                        self.send_to_target(route, "Hello from start node!")
                else:
                    pass
                    # print(f"{self.name}: Hash mismatch in path backtracking")

            except Exception as e:
                print(f"Path error: {e}")
        elif(data['type'] == "find"):
            try:
                target_hash = data["hash"]
                route = list(data['route'])
                debug_route = list(data['debug_route'])
                debug_route_f = debug_route[0]
                name_to_find = debug_route_f['name']
                # print(f"Find data: {data}")
                first_node = route[0]
                hash_to_find = target_hash
                salt = data["salt"]
                my_hash = self.compute_hashed_identity(salt)
                if(len(route) > 20):
                    route_member = {"hash":my_hash,"salt":salt}
                    debug_route_member = {"name":self.name,"len_route":len(route)}
                    debug_route = list(data['debug_route'])
                    debug_route.append(debug_route_member)
                    
                    ret_data = {"type":"path","hash":target_hash,"salt": salt,"route":route,"count":len(route)-1,"debug_route":debug_route, "message_id": str(uuid.uuid4())}
                    # print(f"Failed to find({self.name})")
                    self.return_path(ret_data)
                    # print("Failed to find")
                # if(my_hash == hash_to_find):
                    # print(f"name: {self.name}|{name_to_find}")
                if(my_hash == hash_to_find):
                    route_member = {"hash":my_hash,"salt":salt}
                    route.append(route_member)
                    debug_route_member = {"name":self.name,"len_route":len(route)}
                    debug_route = list(data['debug_route'])
                    debug_route.append(debug_route_member)
                    ret_data = {"type":"path","route":route,"count":len(route)-1,"debug_route":debug_route,"hash":target_hash,"salt":salt, "message_id": str(uuid.uuid4())}
                    print(f"{self.name}: FOUND THE ROUTE")
                    self.return_path(ret_data)
                    # Will now send ret data BACK up the route
                else:
                    route_member = {"hash":my_hash,"salt":salt}
                    route.append(route_member)
                    debug_route_member = {"name":self.name,"len_route":len(route)}
                    debug_route = list(data['debug_route'])
                    debug_route.append(debug_route_member)
                    self.continue_find(route,hash_to_find=hash_to_find,debug_route=debug_route,target=target_hash,salt=salt)
            except Exception as e:
                print(f"find error {e}|{data}")

    def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind(('0.0.0.0', self.port))
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
                        # self.neighbors[addr] = None
                        self.handle_conn(json_data,addr)

                    except json.JSONDecodeError as e:
                        print(f"[!] JSON decode error: {e}")
                    except Exception as e:
                        print(f"[!] General error: {e}")
                    finally:
                        pass
                        # print("[*] Connection closed.\n")


def build_neighbor_map(nodes):
    neighbor_map = {}
    for node in nodes:
        neighbor_map[node.name] = [neighbor.name for neighbor in nodes if (neighbor.port, None) in node.neighbors]
    return neighbor_map

def find_path(neighbor_map, start_name, target_name):
    visited = set()
    queue = deque([[start_name]])

    while queue:
        path = queue.popleft()
        current = path[-1]

        if current == target_name:
            return path

        if current not in visited:
            visited.add(current)
            for neighbor in neighbor_map.get(current, []):
                new_path = list(path)
                new_path.append(neighbor)
                queue.append(new_path)

    return None

BASE_PORT = 5000
NUM_NODES = 200
NEIGHBOR_COUNT = 5  # or 50 as in your earlier snippet
def main():
    nodes = []
    ports = list(range(BASE_PORT, BASE_PORT + NUM_NODES))
    addresses = [("127.0.0.1", port) for port in ports]

    for i, port in enumerate(ports):
        name = f"Node{i}"
        bootstrap_candidates = [addr for j, addr in enumerate(addresses) if j != i]
        bootstrap_ips = random.sample(bootstrap_candidates, NEIGHBOR_COUNT)
        node = NetNode(name=name, port=port, bootstrap_ips=bootstrap_ips)
        nodes.append(node)

    # Start listeners
    for node in nodes:
        threading.Thread(target=node.listen, daemon=True).start()

    print("[+] All nodes launched and listening.")

    time.sleep(2)

    for node in nodes:
        threading.Thread(target=node.build_network).start()

    time.sleep(2)

    # Build name-to-node map for lookup
    name_map = {node.name: node for node in nodes}

    # Select start and target node
    start_node, target_node = random.sample(nodes, 2)
    print(f"[→] Start node: {start_node.name}")
    print(f"[🎯] Target node: {target_node.name}")

    # Check if they are connected via declared neighbor relationships
    neighbor_map = {}
    for node in nodes:
        neighbor_names = []
        for ip, _ in node.neighbors.items():
            for n in nodes:
                if n.port == ip[1]:  # match by port
                    neighbor_names.append(n.name)
        neighbor_map[node.name] = neighbor_names

    # Find a naive unencrypted path
    path = find_path(neighbor_map, start_node.name, target_node.name)
    if path:
        print(f"[🧭] Path exists from {start_node.name} to {target_node.name}: {' → '.join(path)}")
        print(f"Path len: {len(path)}")
    else:
        print(f"[❌] No path found between {start_node.name} and {target_node.name}")

    # Start the hashed search
    salt = "fixed_salt_123"
    start_node.start_find(target_name=target_node.name, salt=salt)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[*] Shutting down.")
main()


def hybrid_encrypt(data: bytes, public_key) -> bytes:
    # Generate random AES key
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # Encrypt data with AES
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt AES key with RSA public key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Package: encrypted_key_length (2 bytes) + encrypted_key + iv + encrypted_data
    ek_len = len(encrypted_key).to_bytes(2, 'big')
    return ek_len + encrypted_key + iv + encrypted_data

def hybrid_decrypt(data: bytes, private_key) -> Optional[bytes]:
    try:
        ek_len = int.from_bytes(data[:2], 'big')
        encrypted_key = data[2:2+ek_len]
        iv = data[2+ek_len:2+ek_len+16]
        encrypted_data = data[2+ek_len+16:]

        # Decrypt AES key with RSA private key
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        # Decrypt data with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    except Exception:
        return None
