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
from datetime import datetime, timezone, timedelta
#TODO Make stored ip,port combos to hash, time bombed, Decide on encryption
class NetNode():
    def __init__(self, name: str,port,bootstrap_ips:list):
        self.name = name
        self.id = uuid.uuid4().hex
        # self._generate_keys()
        self.neighbors = {}
        self.neighbors_hash = {}

        for ip in bootstrap_ips:
            self.neighbors[ip] = None
        for ip in bootstrap_ips:
            self.neighbors_hash[ip] = None
        self.port = port
        self.ip = '127.0.0.1'
        self.max_neighbors = 5
        self.seen_messages = set()
        self.found_route = False
        self.store_hash = {}
        self.store_hash_time = {}
        self.handled_paths = set()
        self.send_lock = False
        self.send_loop_count = 0
        self.find_hashes_handled = set()
        self.found_end_route = {}

        self.found_paths = {}
        self.failed_paths = {}

        self.is_connect_node = False
        # self.build_neighbors() #! USe this in dev
    def build_neighbors(self):
        self.neighbors_tmp = set()
        for ip,key in self.neighbors.items():
            self.neighbors_tmp.add(ip)
        for ip in self.neighbors_tmp:
            tup = ('127.0.0.1',self.port)
            packet = {"type":"neighbors","ip_key":tup}
            ret = self.send_data(packet,addr=ip,init_con=True)
            if(ret == False):
                time.sleep(1)
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
    def ask_for_hash(self,salt):
        packet = {"type":"hash_req","salt":salt}
        json_str = json.dumps(packet)
        encoded = json_str.encode('utf-8')
        for ip, key in self.neighbors.items(): 
            host, port = ip
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                client_socket.sendall(encoded)
            time.sleep(0.05)
    def log_hashes(self,ip,packet):
        n_hash = packet["hash"]
        n_salt = packet["salt"]
        key = (n_salt, ip)
        self.neighbors_hash[key] = n_hash
    def post_packet(self,packet,target_name,salt):
        target_hash = self.start_find(target_name,salt)
        # print("Tarhet hash post",target_hash)
        max_check_time = 10 # seconds
        start_time = time.time()
        path = self.found_paths.get(target_hash,None)
        
        while path == None:
            failed_trys = self.failed_paths.get(target_hash,0)
            if failed_trys >= 10:
                print("Failed to find path after multiple attempts.")
                return False
            time.sleep(0.05)
            current_time = time.time()
            # if(current_time-start_time > max_check_time):
            #     print("Timeout waiting for path to be found.")
            #     return False
            path = self.found_paths.get(target_hash,None)
            # print(path)
            # print("polling",start_time-current_time)
        self.failed_paths[target_hash] = 0
        self.send_to_target(path,packet)
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
    def send_data(self,data,addr=None,conn=None,debug_node_name=None,init_con=False):
        
        while(self.send_lock == True):
            pass
        if(self.is_connect_node == True):
            print(f"{self.name}: Send data to {addr}: Data: \n{data}")
        # if(debug_node_name == None):
            # print("WHY?")
        debug_node_n  =debug_node_name
        self.send_lock = True
        message_id = data.get("message_id",None)
        if(message_id is None):
            message_id = str(uuid.uuid4())
        data['message_id'] = message_id
        host, port = addr  # Unpack the address tuple
        try:
            json_str = json.dumps(data)
            encoded = json_str.encode('utf-8')

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                client_socket.sendall(encoded)
            time.sleep(0.05)
            self.send_loop_count = 0
            self.send_lock = False
                # print(f"[√] Sent JSON to {host}:{port}")
        except Exception as e:
            if(init_con == False):
                self.send_lock = False
                time.sleep(0.05)
                self.send_loop_count += 1
                # if(self.send_loop_count < 10):
                    # self.send_data(data,addr=addr,debug_node_name=debug_node_n)
                # print(e)
                # if(debug_node_n != "cont find"):
                print(f"[!]{self.name} Error sending JSON to {host}:{port}:{debug_node_n} - {e}")
            else:
                return False
    def temp(self):
        route = []
        route_member = {"node_hash":"the nodes named, hashed ","salt":"the salt used to hash the name"}
        ## Packet:
        packet_find = {"type":"find","route":route,"hash":"the hash to find","key":"the last nodes RSA key(this nodes rsa if it is sending it)"}
    def continue_find(self,route,hash_to_find,debug_route=None,target=None,salt=None,my_ip=None):
        packet = {"type":"find","route":route,"hash":target,"salt":salt, "message_id": str(uuid.uuid4()),"my_ip":my_ip}
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        
        for ip, key in self.neighbors.items():
            
            # will later handle key encryption
            self.send_data(packet,ip,debug_node_name="cont find")

    def return_path(self,path,addr=None,debug_node_name=None):
        # message_id = path.get("message_id",None)
        # # if(message_id == None):print("retuern None")
        # salt = path.get("salt",None)
        # path["message_id"] = message_id or str(uuid.uuid4())
        count = path.get("count",None)
        route = path.get("route",None)
        # self.ask_for_hash(salt)'
        if(addr == None):
            for ip, key in self.neighbors.items():
                # if(self.neighbors_hash.get(key,None) == route[count - 1]):
                self.send_data(path,ip,debug_node_name=f"Scan send: {debug_node_name}")
        else:
            host, port = addr
            # print(host,port)
            self.send_data(path,addr=addr,debug_node_name=debug_node_name)
    def hash_str(self,name,salt):
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    def start_find(self, target_name: str, salt: str):
        target_hash = self.hash_str(target_name, salt)  # FIXED
        my_hash = self.compute_hashed_identity(salt)
        route_member = {"hash": my_hash, "salt": salt}
        route = [route_member]
        # debug_route_member = {"name":self.name,"len_route":len(route)}
        route = [route_member]
        # debug_route = [debug_route_member]

        packet = {
            "type": "find",
            "route": route,
            "hash": target_hash,
            "salt": salt,
            # "key": self.public_key.public_bytes(
            #     encoding=serialization.Encoding.PEM,
            #     format=serialization.PublicFormat.SubjectPublicKeyInfo
            # ).decode(),
            
            "message_id": str(uuid.uuid4()),
            "my_ip":(self.ip,self.port)
        }
        # print((self.ip,self.port))
        for ip, key in self.neighbors.items():
            # will later handle key encryption
            self.send_data(packet,ip,debug_node_name="send packet")
        # self.continue_find(route, target_hash)
        print("Find target hash: ",target_hash)
        return target_hash
    def return_to_sender(self, route, payload):
        count = len(route) - 2
        packet = {
            "type": "return",
            "route": route,
            "count": count,
            "payload": payload
        }
        # Send to previous hop
        for ip, _ in self.neighbors.items():
            self.send_data(packet, ip,"return_to_sender")
    def send_to_target(self, route, payload):
        count = 1
        packet = {
            "type": "forward",
            "route": route,
            "count": count,
            "payload": payload
        }
        # Send to next hop
        next_hop = route[count]
        print("Next hop",next_hop)
        time.sleep(1)
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        for ip, _ in self.neighbors.items():
            self.send_data(packet, ip,"send to target")

    def handle_conn(self,data,addr,conn):
        # print(data)
        message_id = data.get("message_id")
        if message_id != None and message_id in self.seen_messages:
            if(data.get("type",None) == "path"):
                print("discard path: ",data.get("message_id"))
            return  # Drop duplicate
        # if(not message_id):
        #     print("U missed one")
        # Otherwise:
        if message_id:
            self.seen_messages.add(message_id)
        if(data["type"] == "get_rsa"):
            key = self.public_key
            key_data = {"key",key}
            self.send_data(key_data, addr,"rsa get")
        elif(data["type"] == "connect"):
            print('connect')
            self.is_connect_node = True
            ip_port_combo = tuple(data.get("tup"))
            self.neighbors[ip_port_combo] = None
            for ip,key in self.neighbors.items():
                print(ip,key)
        elif data['type'] == "neighbors":
            ip_port = tuple(data.get("tup"))
            self.neighbors[ip_port] = None
        elif(data["type"] == "hash_req"):
            use_salt = data["salt"]
            my_hash = self.compute_hashed_identity(use_salt)
            res = {"type":"hash_res","hash":my_hash,"salt":use_salt}
            host,port = addr
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
        elif(data["type"] == "hash_res"):
            self.log_hashes(addr,data)
        elif data['type'] == "return":
            try:
                # print("reterning")
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
                        hash_to_search = route[count-1]["hash"]
                        try:
                            val = tuple(self.store_hash.get(hash_to_search,None))
                        except:
                            val = None
                        if(val != None):
                            self.send_data(next_packet, val,"type return")
                        else:
                            for ip, _ in self.neighbors.items():
                                self.send_data(next_packet, ip,"type return")
                    else:
                        print(f"[⬅️] Final ACK received at {self.name}: {payload}")
            except Exception as e:
                print(f"[!] {self.name}Return error: {e}")
        elif data['type'] == "forward":
            try:
                
                route = data["route"]
                count = int(data["count"])
                payload = data["payload"]
                my_hash = self.compute_hashed_identity(route[count]["salt"])

                if self.compute_hashed_identity(route[count]["salt"]) == route[count]["hash"]:
                    # print("forwarding packets")
                    if count + 1 < len(route):
                        next_packet = {
                            "type": "forward",
                            "route": route,
                            "count": count + 1,
                            "payload": payload
                        
                        }
                        
                        for ip, _ in self.neighbors.items():
                            self.send_data(next_packet, ip,"type forward")
                    else:
                        print(f"[🎯] {self.name} received payload: {payload}")
                        self.return_to_sender(route, f"ACK from {self.name}")
            except Exception as e:
                print(f"[!] {self.name}Forward error: {e}")

        elif data["type"] == "path":
            
            message_id = data["message_id"]
            if(message_id in self.handled_paths):
                print(f"ignored")
                return
            self.handled_paths.add(message_id)
            try:
                # debug_route = data["debug_route"]
                sub_type = data.get("sub_type", "default")
                
                count = int(data["count"])
                name_route = []
                # for mem in debug_route:
                #     name_route.append(mem.get("name"))
                # out = ' → '.join(name_route)
                # print(out)
                # print("------")
                # print(f"Current postion: {count}")
                # print(f"This node: {self.name}:Needed Node: {debug_route[count].get("name")}\nPATH received: {out}")
                
                # print("---------")
                # print(f"current node {debug_route[count]}")
                # print("")
                route = data['route']
                
                

                my_member = route[count]
                try:
                    my_hash = self.compute_hashed_identity(my_member["salt"])
                except Exception as e:
                    print(f"Hashing error {e}")
                # my_member_deb = debug_route[count]
                # print(f"Name:{self.name}:{my_member_deb["name"]}")
                # if(self.name == my_member_deb['name']):
                #     print("Match")
                #     if my_hash == my_member["hash"]:
                #         print("Hash work")
                #     else:
                #         print("Hash not work")
                if my_hash == my_member["hash"]:
                    # print(f"{self.name}: Stepping back from: {count}")
                    if count > 0:
                        data['count'] = count - 1
                        # print(f"{data['count']}")
                        
                        that_hash = route[data['count']]["hash"]
                        # that_hash_name = debug_route[data['count']]
                        # print(f"Next node: {that_hash_name.get("name")}|Current node: {self.name}")
                        if(my_hash == that_hash):
                            # print("How?")
                            that_hash = route[count-1]["hash"]
                            # that_hash_name = debug_route[count-1]
                            data['count'] = count - 2
                        end_hash = route[len(route)-1]["hash"]
                        if(that_hash == end_hash):
                            print("This shouldn't happen")
                        if(self.store_hash.get(that_hash,None) != None):
                            # print("That worked",tuple(self.store_hash.get(that_hash,None)))
                            val = tuple(self.store_hash.get(that_hash,None))
                            if(val == None):
                                print("Error")
                            self.return_path(data,val)
                        else:
                            print("Error with cache")
                            # self.return_path(data,debug_node_name="other loop")
                    else:
                        if(sub_type == "default"):
                            print(f"{self.name}: Back at main")
                            try:
                                end_hash = route[len(route)-1]
                            except Exception as e:
                                print(f"End hash error {e}")
                            try:
                                self.found_paths[end_hash.get("hash",None)] = route
                                print("end_hash.get('name',None) == ",end_hash.get("hash",None))
                            except Exception as e:
                                print(f"Logging found error {e}")
                            try:
                                # print("send route",route)
                                # self.send_to_target(route, "Hello from start node!")
                                pass
                            except Exception as e:
                                print(f"Send error {e}")
                        else:
                            # print(f"{self.name},Got path return of type no_path. Adding to failed pathfinding attempts")
                            try:
                                end_hash = route[len(route)-1]
                            except Exception as e:
                                print(f"End hash error {e}")
                            try:
                                inc = int(self.failed_paths.get(data.get("hash",None),0))
                                inc+=1
                                self.failed_paths[data.get("hash",None)] = inc

                                # print("end_hash.get('name',None) == ",end_hash.get("hash",None))
                            except Exception as e:
                                print(f"Logging found error {e}")

                else:
                    return
                    # print(f"{self.name}: Hash mismatch in path backtracking")

            except Exception as e:
                for item in data.keys():
                    print(data[item],"|",type(data[item]))
                print(f"{self.name} Path error: {e}")
        elif(data['type'] == "find"):
            try:
                
                target_hash = data["hash"]
                route = list(data['route'])
                if(self.found_end_route.get(target_hash,None) == route[0].get("hash")):
                    return
                if(target_hash in self.find_hashes_handled):
                    return
                self.find_hashes_handled.add(target_hash)
                
                # debug_route = list(data['debug_route'])
                # debug_route_f = debug_route[0]
                # name_to_find = debug_route_f['name']
                last_ip = data.get("my_ip",None)
                self.store_hash[route[len(route)-1].get("hash")] = last_ip
                self.store_hash_time[route[len(route)-1].get("hash")] = datetime.now(timezone.utc)
                # TODO Make timeout for store_hash

                # print(f"Find data: {data}")
                first_node = route[0]
                hash_to_find = target_hash
                salt = data["salt"]
                my_hash = self.compute_hashed_identity(salt)
                if(len(route) > 20):
                    # print("Killing search")
                    route_member = {"hash":my_hash,"salt":salt}
                    # debug_route_member = {"name":self.name,"len_route":len(route)}
                    # debug_route = list(data['debug_route'])
                    # debug_route.append(debug_route_member)
                    message_id = data.get("message_id",None)
                    ret_data = {"type":"path","sub_type":"no_path","hash":target_hash,"salt": salt,"route":route,"count":len(route)-1}
                    that_hash = route[int(ret_data["count"])]["hash"]
                    # that_hash_name = debug_route[int(ret_data["count"])]["name"]
                    if(self.store_hash.get(that_hash,None) != None):
                        # print("That worked",tuple(self.store_hash.get(that_hash,None)))
                        val = tuple(self.store_hash.get(that_hash,None))
                        if(val == None):
                            print("Error")
                        self.return_path(ret_data,val)
                    else:
                        print("No match")
                    # return
                    # print(f"Failed to find({self.name})")
                    # self.return_path(ret_data)
                    # print("Failed to find")
                # if(my_hash == hash_to_find):
                    # print(f"name: {self.name}|{name_to_find}")
                if(my_hash == hash_to_find):
                    self.found_end_route[target_hash] = route[0].get("hash")
                    route_member = {"hash":my_hash,"salt":salt}
                    route.append(route_member)
                    # debug_route_member = {"name":self.name,"len_route":len(route)}
                    # debug_route = list(data['debug_route'])
                    # debug_route.append(debug_route_member)
                    ret_data = {"type":"path","route":route,"count":len(route)-2,"hash":target_hash,"salt":salt}
                    ret_data["message_id"] = str(uuid.uuid4())
                    # print(f"LAST NODE : {debug_route[len(route)-2]}")
                    # ret_data = {"type":"path","hash":target_hash,"salt": salt,"route":route,"count":len(route)-1,"debug_route":debug_route}

                    # print(f"{self.name}: {data.get("message_id")}: FOUND THE ROUTE:")
                    self.found_route = True
                    name_route = []
                    # for mem in debug_route:
                    #     name_route.append(mem.get("name"))
                    # out = ' → '.join(name_route)
                    # print(out)

                    that_hash = route[int(ret_data["count"])]["hash"]
                    # that_hash_name = debug_route[int(ret_data["count"])]["name"]
                    if(self.store_hash.get(that_hash,None) != None):
                        # print("That worked",tuple(self.store_hash.get(that_hash,None)))
                        val = tuple(self.store_hash.get(that_hash,None))
                        if(val == None):
                            print("Error")
                        self.return_path(ret_data,val)
                    else:
                        print("No match")
                        # self.return_path(ret_data,debug_node_name="other run")
                # self.return_path(ret_data)
                    # Will now send ret data BACK up the route
                else:
                    route_member = {"hash":my_hash,"salt":salt}
                    route.append(route_member)
                    # debug_route_member = {"name":self.name,"len_route":len(route)}
                    # debug_route = list(data['debug_route'])
                    # debug_route.append(debug_route_member)
                    
                    self.store_hash[route[len(route)-1].get("hash")] = last_ip
                    my_ip = (self.ip,self.port)
                    # print(">>",my_ip)
                    # for ip, _ in self.neighbors.items():
                    #     print(ip)
                    # time.sleep(10)
                    self.continue_find(route,hash_to_find=hash_to_find,target=target_hash,salt=salt,my_ip=my_ip)
            except Exception as e:
                print(f"{self.name} find error {e}|{data}")

    def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                        self.handle_conn(json_data,addr,conn)

                    except json.JSONDecodeError as e:
                        print(f"[!]{self.name} JSON decode error: {e}")
                    except Exception as e:
                        print(f"[!]{self.name} General error: {e}")
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
    for node in nodes:
        for ip, _ in node.neighbors.items():
            # Find the actual node object corresponding to this IP
            for other_node in nodes:
                if ('127.0.0.1', other_node.port) == ip:
                    if (('127.0.0.1', node.port) not in other_node.neighbors):
                        other_node.neighbors[('127.0.0.1', node.port)] = None
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
    ##! This is debug dat. Only for testing purposes.
    start_node, target_node = random.sample(nodes, 2)
    # print(f"[→] Start node: {start_node.name}")
    # print(f"[🎯] Target node: {target_node.name}")
    
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
    # if path:
    #     print(f"[🧭] Path exists from {start_node.name} to {target_node.name}: {' → '.join(path)}")
    #     print(f"Path len: {len(path)}")
    # else:
    #     print(f"[❌] No path found between {start_node.name} and {target_node.name}")
    ##! End of debug data.
    # import base64
    # Start the hashed search
    # salt_ur = os.urandom(32)
    # salt = base64.b64
    # salt = os.urandom(32).decode('latin-1')
    # find_c = input(">>")
    # while find_c != "end":
    #     data_in = input("Enter data to send: ")
    #     packet = data_in
    #     start_node.post_packet(packet,find_c,salt)
    #     find_c = input(">>")

    # start_node.start_find(target_name=target_node.name, salt=salt)

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

# f13e17308af7a8a97ed09c2c9904a5d29b54509bf468cd1eb0e6b50dfd243dce
# f13e17308af7a8a97ed09c2c9904a5d29b54509bf468cd1eb0e6b50dfd243dce
    

# 8,11
    