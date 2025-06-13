from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

import random
import uuid
from typing import List, Optional, Set
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import socket
import json
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
# nodes = [Node(f"Node{i}") for i in range(NUM_NODES)]
# for node in nodes:
#     node.neighbors = random.sample([n for n in nodes if n != node], NEIGHBOR_COUNT)

class NetNode():
    def __init__(self, name: str,ip,bootstrap_ips:list):
        self.name = name
        self.id = uuid.uuid4().hex
        self._generate_keys()
        self.neighbors = {}
        for ip in bootstrap_ips:
            self.neighbors[ip] = None
        self.ip = ip
        self.max_neighbors = 5
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
                print(f"Requesting public key from {ip}...")
                
                # This part will request a key from that server
                fake_key = None
                
                # Store the received key
                self.neighbors[ip] = fake_key
                print(f"Received and stored key from {ip}: {fake_key}")
            
    
        pass # Will send RSA public key
    def send_data(self,data,addr):
        host, port = addr  # Unpack the address tuple
        try:
            json_str = json.dumps(data)
            encoded = json_str.encode('utf-8')

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                client_socket.sendall(encoded)
                print(f"[√] Sent JSON to {host}:{port}")
        except Exception as e:
            print(f"[!] Error sending JSON to {host}:{port} - {e}")
    def temp(self):
        route = []
        route_member = {"node_hash":"the nodes named, hashed ","salt":"the salt used to hash the name"}
        ## Packet:
        packet_find = {"type":"find","route":route,"hash":"the hash to find","key":"the last nodes RSA key(this nodes rsa if it is sending it)"}
    def continue_find(self,route,hash_to_find):
        packet = {"type":"find","route":route,"hash":hash_to_find}
        for ip, key in self.neighbors.items():
            # will later handle key encryption
            self.send_data(packet,ip)
    def return_path(self,path):
        for ip, key in self.neighbors.items():
            self.send_data(path,ip)

    def handle_conn(self,data,addr):
        if(data["type"] == "get_rsa"):
            key = self.public_key
            key_data = {"key",key}
            self.send_data(key_data, addr)
        elif(data["type"] == "path"):
            route = data[route]
            count = data["count"]
            my_member = route[count]
            route_hash = my_member["hash"]
            route_salt = my_member["salt"]
            my_hash = self.compute_hashed_identity(route_salt)
            if(my_hash == route_hash and count != 0):
                count-=1
                ret_data = data
                ret_data['count'] = count
                self.return_path(ret_data)
            elif(my_hash == route_hash and count == 0):
                print("Back at main")
            # pass
        elif(data['type'] == "find"):
            hash_to_find = data["hash"]
            salt = data['salt']
            my_hash = self.compute_hashed_identity(salt)
            route = list(data['route'])
            if(my_hash == hash_to_find):
                route_member = {"hash":my_hash,"salt":salt}
                route.append(route_member)
                ret_data = {"type":"path","route":route,"count":len(route)}
                self.return_path(ret_data)
                # Will now send ret data BACK up the route

            else:
                route_member = {"hash":my_hash,"salt":salt}
                route.append(route_member)
                self.continue_find(route,hash_to_find=hash_to_find)

    def listen(self,port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen()
            print(f"[+] Listening forever on port {port}...")

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
                        print(f"[>] Full raw data: {decoded}")

                        json_data = json.loads(decoded)
                        print(f"[√] Received JSON: {json_data}")
                        self.handle_conn(json_data,addr)

                    except json.JSONDecodeError as e:
                        print(f"[!] JSON decode error: {e}")
                    except Exception as e:
                        print(f"[!] General error: {e}")
                    finally:
                        print("[*] Connection closed.\n")
    def check(self,name,salt,cur_path):
        if(self.compute_hashed_identity(salt) == name):
            pass #Handle match
        else:
            pass #convert path to list. Add itself, query neighbors
# --- Recursive Discovery ---
def recursive_discovery(
    current_node: Node,
    encrypted_hash: bytes,
    salt: str,
    visited: Set[Node],
    path: List[Node],
    target_hash: str,
    max_depth: int = 10
) -> Optional[List[Node]]:
    if current_node in visited or max_depth <= 0:
        return None
    visited.add(current_node)

    decrypted = current_node.decrypt(encrypted_hash)
    if not decrypted:
        return None

    try:
        decrypted_text = decrypted.decode()
        extracted_hash, extracted_salt = decrypted_text.split("::")
    except Exception:
        return None

    current_hashed = current_node.compute_hashed_identity(extracted_salt)
    if current_hashed == target_hash:
        return path + [current_node]

    for neighbor in current_node.neighbors:
        new_encrypted = neighbor.encrypt(f"{extracted_hash}::{extracted_salt}".encode())
        result = recursive_discovery(
            neighbor, new_encrypted, extracted_salt,
            visited, path + [current_node], target_hash, max_depth - 1
        )
        if result:
            return result
    return None


# --- Onion Wrap / Unwrap ---
def wrap_return_path(path: List[Node], payload: str) -> bytes:
    data = payload.encode()
    for node in reversed(path):
        data = node.encrypt(data)
    return data


def unwrap_return_path(path: List[Node], payload: bytes) -> str:
    data = payload
    for node in path:
        data = node.decrypt(data)
        if data is None:
            return "[Decryption Failed]"
    return data.decode()


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
