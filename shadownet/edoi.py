from collections import defaultdict
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
import asyncio
class NetNode():
    def __init__(self, name: str,port,bootstrap_ips:list):
        self.name = name # The name of this node on the network
        self.id = uuid.uuid4().hex # Unique ID of node
        # self._generate_keys()
        self.neighbors = {} # List of all neighboring nodes (ip,port) combos, Previously stored RSA keys
        self.neighbors_hash = {} # List of all neighboring nodes hash. 

        # Initiate all neighbors with IP
        for ip in bootstrap_ips:
            self.neighbors[ip] = None 
        for ip in bootstrap_ips:
            self.neighbors_hash[ip] = None
        self.port = port # Port this server will listen on
        self.ip = '127.0.0.1' # IP server will listen on
        self.max_neighbors = 5 # Max number of neighbors
        self.seen_messages = set() # Set of all seed messages
        self.found_route = False # Unused
        self.store_hash = {} # Stored hash to IP combos per search
        self.store_hash_time = {} # Time for store_hash, used to delete old
        self.handled_paths = set() # Set of all handled path messages
        self.send_lock = False # Lock to disable send to avoid threading error
        self.send_loop_count = 0 # Loop to check for send count, unused in node mode
        self.find_hashes_handled = set() # Set of all hashes already checked
        self.found_hash_routes = set() # Set of all found hash routes, used to avoid duplicates
        self.found_end_route = {} # List of all end routes found
        self.found_end_routes = {}
        # Used if node is bas
        self.found_paths = {}
        self.failed_paths = {}

        #Flag to allow other outside nodes to connect
        self.is_connect_node = False
        threading.Thread(target=self.memory_cleaner,daemon=True).start()
        # self.build_neighbors() #! USe this in dev
    def memory_cleaner(self):
        # while True:
        #     try:
        #         rem_hash_val = []
        #         for hash_val, time_str in list(self.store_hash_time.items()):
        #             try:
        #                 # print(time_str,type(time_str))
        #                 timestamp = datetime.fromisoformat(time_str)
        #             except ValueError:
        #                 print(f"[WARN] Invalid ISO time string: {time_str}")
        #                 continue
        #             now = datetime.now(timezone.utc)
        #             if now - timestamp > timedelta(seconds=3):
        #                 # print("Clearing path:", hash_val)
        #                 rem_hash_val.append(hash_val)
        #         for i in rem_hash_val:
        #             self.store_hash.pop(i, None)
        #             self.store_hash_time.pop(i, None)
        #     except Exception as e:
        #         print("[ERROR] Memory cleaner exception:", e)
        #     time.sleep(1)
        pass
    async def build_neighbors(self):
        self.neighbors_tmp = set()
        for ip,key in self.neighbors.items():
            self.neighbors_tmp.add(ip)
        for ip in self.neighbors_tmp:
            tup = ('127.0.0.1',self.port)
            packet = {"type":"neighbors","ip_key":tup}
            ret = await self.send_data(packet,addr=ip,init_con=True)
            if(ret == False):
                time.sleep(1)
    
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
    async def send_data(self, data, addr=None, conn=None, debug_node_name=None, init_con=False):
        while self.send_lock:
            await asyncio.sleep(0.001)  # Yield control instead of busy-waiting
        
        self.send_lock = True
        # print(debug_node_name)
        # if(debug_node_name == "return"):
        #     # print("THIS IS A RETURN PACKET")
        #     print(f"{self.name}: Got return packet at time {conn}")
        #     print(f"{self.name}: Send return packet at time {time.time()}")
            
        # elif(debug_node_name == "forward"):
        #     # print("THIS IS A FORWARD PACKET")
        #     print(f"{self.name}: Got forward packet at time {conn}")

        #     print(f"{self.name}: Sent forward packets at {time.time()}")
        if self.is_connect_node:
            # print(f"{self.name}: Send data to {addr}: Data: \n{data}")
            pass

        message_id = data.get("message_id", str(uuid.uuid4()))
        data["message_id"] = message_id
        host, port = addr
        # if(port == 5400):
            # print(f"[!] {self.name} Sending data to {host}:{port} - {data}")

        try:
            json_str = json.dumps(data)
            encoded = json_str.encode("utf-8")

            reader, writer = await asyncio.open_connection(host, port)
            writer.write(encoded)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            await asyncio.sleep(0.05)
            self.send_loop_count = 0
            self.send_lock = False
            # print(f"[√] Sent JSON to {host}:{port}")
        except Exception as e:
            self.send_lock = False
            await asyncio.sleep(0.05)
            self.send_loop_count += 1
            if not init_con:
                print(f"[!]{self.name} Error sending JSON to {host}:{port}:{debug_node_name} - {e}")
            else:
                return False
    def temp(self):
        route = []
        route_member = {"node_hash":"the nodes named, hashed ","salt":"the salt used to hash the name"}
        ## Packet:
        packet_find = {"type":"find","route":route,"hash":"the hash to find","key":"the last nodes RSA key(this nodes rsa if it is sending it)"}
    async def continue_find(self,route,hash_to_find,debug_route=None,target=None,salt=None,my_ip=None):
        packet = {"type":"find","route":route,"hash":target,"salt":salt, "message_id": str(uuid.uuid4()),"my_ip":my_ip}
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        
        for ip, key in self.neighbors.items():
            
            # will later handle key encryption
            await self.send_data(packet,ip,debug_node_name="cont find")

    async def return_path(self,path,addr=None,debug_node_name=None):
        # message_id = path.get("message_id",None)
        # # if(message_id == None):print("retuern None")
        # salt = path.get("salt",None)
        # path["message_id"] = message_id or str(uuid.uuid4())
        count = path.get("count",None)
        route = path.get("route",None)
        # self.ask_for_hash(salt)'
        if(addr == None):
            # print(f"{self.name} ALT SEND")
            for ip, key in self.neighbors.items():
                # if(self.neighbors_hash.get(key,None) == route[count - 1]):
                await self.send_data(path,ip,debug_node_name=f"Scan send: {debug_node_name}")
        else:
            host, port = addr
            
            # print(host,port)
            await self.send_data(path,addr=addr,debug_node_name=debug_node_name)
    async def hash_str(self,name,salt):
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    async def start_find(self, target_name: str, salt: str):
        print("FIND")
        target_hash = await self.hash_str(target_name, salt)  # FIXED
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
            await self.send_data(packet,ip,debug_node_name="send packet")
        # self.continue_find(route, target_hash)
        # print("Find target hash: ",target_hash)
        return target_hash
    async def return_to_sender(self, route, payload):
        count = len(route) - 2
        packet = {
            "type": "return",
            "route": route,
            "count": count,
            "ip_combo":tuple(self.ip, self.port),
            "payload": payload
        }
        # Send to previous hop
        for ip, _ in self.neighbors.items():
            await self.send_data(packet, ip,"return_to_sender")
    async def send_to_target(self, route, payload):
        count = 1
        packet = {
            "type": "forward",
            "route": route,
            "count": count,
            "payload": payload
        }
        # Send to next hop
        # next_hop = route[count]
        # print("Next hop",next_hop)
        time.sleep(1)
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        for ip, _ in self.neighbors.items():
            await self.send_data(packet, ip,"send to target")

    async def handle_conn(self,data,addr,conn):
        # print(self.name,"||",data)
        message_id = data.get("message_id")
        # if message_id != None and message_id in self.seen_messages:
            # if(data.get("type",None) == "path"):
            #     print("discard path: ",data.get("message_id"))
            # else:
            #     return  # Drop duplicate
        # if(not message_id):
        #     print("U missed one")
        # Otherwise:
        if message_id:
            self.seen_messages.add(message_id)
        if(data["type"] == "get_rsa"):
            key = self.public_key
            key_data = {"key",key}
            await self.send_data(key_data, addr,"rsa get")
        elif(data["type"] == "connect"):
            print(self.name,'connect')
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
                got_return_packet_time = time.time()
                route = data["route"]
                count = int(data["count"])
                payload = data["payload"]
                my_hash = self.compute_hashed_identity(route[count]["salt"])

                if my_hash == route[count]["hash"]:
                    past_hash = route[count + 1]["hash"]
                    if past_hash == my_hash:
                        print("THis is wrong")
                        return  # Ignore if the hash matches the previous one
                    else:
                        ip_combo = data.get("ip_combo",None)
                        if(ip_combo != None):
                            self.store_hash[past_hash]  = ip_combo
                    if count > 0:
                        combo = (self.ip,self.port)
                        # print("combo: ",combo)
                        next_packet = {
                            "type": "return",
                            "route": route,
                            "count": count - 1,
                            "ip_combo":combo,
                            "payload": payload
                        }
                        hash_to_search = route[count]["hash"]
                        try:
                            val = tuple(self.store_hash.get(hash_to_search,None))
                        except Exception as e:
                            print(e, "Error retrieving value from store_hash for hash:", hash_to_search)
                            val = None
                        if(val != None):
                            self.store_hash_time[hash_to_search] = datetime.now(timezone.utc).isoformat()

                            await self.send_data(next_packet, val,debug_node_name="return",conn=got_return_packet_time)
                            # print(f"{self.name}: Got return packet at time: {got_return_packet_time}")
                            # print(f"{self.name}: Send return packet at time {time.time()}")
                            
                        else:
                            # print(f"{self.name}: No stored hash found for {hash_to_search}. Bulk sending")
                            # print(f"{self.name}:Bulk send: Got return packet at time: {got_return_packet_time}")
                            
                            for ip, _ in self.neighbors.items():
                                await self.send_data(next_packet, ip,"type return")
                            # print(f"{self.name}:Bulk send: Send return packet at time {time.time()}")
                    else:
                        print(f"[⬅️] Final ACK received at {self.name}: {payload}")
                else:
                    # 
                    pass
            except Exception as e:
                print(f"[!] {self.name}Return error: {e}")
        elif data['type'] == "forward":
            try:
                # print(data)
                got_forward_packet_start = time.time()
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
                        if(self.store_hash.get(route[count+1].get("hash"),None) != None):
                            self.store_hash_time[route[count+1]["hash"]] = datetime.now(timezone.utc).isoformat()
                            next_ip = tuple(self.store_hash.get(route[count+1]["hash"]))
                            await self.send_data(next_packet, next_ip,debug_node_name="forward",conn=got_forward_packet_start)
                            print(f"{self.name}: Got forward packet at time: {got_forward_packet_start}")
                            print(f"{self.name}: Send forward packet at time {time.time()}")
                        else:
                            print("[❗] No stored hash found for next hop, bulk sending forward packet.")
                            for ip, _ in self.neighbors.items():
                                await self.send_data(next_packet, ip,debug_node_name="forward",conn=got_forward_packet_start)
                            print(f"{self.name}: Got forward packet at time: {got_forward_packet_start}")
                            print(f"{self.name}: Send forward packet at time {time.time()}")
                        
                    else:
                        print(f"[🎯] {self.name} received payload: {payload}")
                        await self.return_to_sender(route, f"ACK from {self.name}")
            except Exception as e:
                print(f"[!] {self.name}Forward error: {e}")

        elif data["type"] == "path":
            
            message_id = data["message_id"]
            if(message_id in self.handled_paths):
                # print(f"ignored")
                return
            # print(self.name,(self.ip,self.port),"Got path")
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
                        # 

                        if(self.store_hash.get(that_hash,None) != None):
                            # print("That worked",tuple(self.store_hash.get(that_hash,None)))
                            self.store_hash_time[that_hash] = datetime.now(timezone.utc).isoformat()

                            val = tuple(self.store_hash.get(that_hash,None))
                            if(val == None):
                                print("Error")
                            await self.return_path(data,val)
                        else:
                            # print(f"{self.name} Error with cache")
                            await self.return_path(data,debug_node_name="other loop")
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
                # for item in data.keys():
                #     print(data[item],"|",type(data[item]))
                print(f"{self.name} Path error: {e}")
        elif(data['type'] == "find"):
            try:
                
                target_hash = data["hash"]
                route = list(data['route'])
                route_hash = hash(tuple(frozenset(item.items()) for item in route))
                route_hashes = list(item.get("hash") for item in route)
                # print(">>",route_hashes)
                route_id = (target_hash, route_hash)
                
                # if route_id in self.find_hashes_handled:
                #     return
                
                # if(self.found_end_route.get(route_id,None) == route[0].get("hash")):
                try:
                    if(route in self.found_end_route.get(route_id,None)):
                        # return
                        return
                except Exception as e:
                    pass
                if(target_hash in self.find_hashes_handled):
                    if(target_hash == route[len(route)-1].get("hash")):
                        print(route)
                #     # print("Handled find hash already, ignoring. Hash") 
                    return
                self.find_hashes_handled.add(target_hash)
                # self.find_hashes_handled.add(target_hash)
                # self.found_hash_routes.add(hashable_route)
                # debug_route = list(data['debug_route'])
                # debug_route_f = debug_route[0]
                # name_to_find = debug_route_f['name']
                last_ip = data.get("my_ip",None)
                self.store_hash[route[len(route)-1].get("hash")] = last_ip
                
                # print("last_ip",type(last_ip))
                self.store_hash_time[route[len(route)-1].get("hash")] = datetime.now(timezone.utc).isoformat()
                

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
                        self.store_hash_time[that_hash] = datetime.now(timezone.utc).isoformat()
                        # print("That worked",tuple(self.store_hash.get(that_hash,None)))
                        val = tuple(self.store_hash.get(that_hash,None))
                        if(val == None):
                            print("Error")
                        await self.return_path(ret_data,val)
                    else:
                        print("No match")
                    # return
                    # print(f"Failed to find({self.name})")
                    # await self.return_path(ret_data)
                    # print("Failed to find")
                # if(my_hash == hash_to_find):
                    # print(f"name: {self.name}|{name_to_find}")
                elif(my_hash == hash_to_find):
                    print("MAtch found")
                    # self.found_end_route[target_hash] = route[0].get("hash")
                    self.found_end_routes.setdefault(route_id, []).append(route)
                    # self.found_end_routes.setdefault(target_hash, []).append(route)
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
                        self.store_hash_time[that_hash] = datetime.now(timezone.utc).isoformat()

                        # print("That worked",tuple(self.store_hash.get(that_hash,None)))
                        val = tuple(self.store_hash.get(that_hash,None))
                        if(val == None):
                            print("Error: No value found for that hash")
                            await self.return_path(ret_data,debug_node_name="other run")
                        await self.return_path(ret_data,val)
                    else:
                        print("No match")
                        await self.return_path(ret_data,debug_node_name="other run")
                # await self.return_path(ret_data)
                    # Will now send ret data BACK up the route
                elif my_hash not in route_hashes:
                    route_member = {"hash":my_hash,"salt":salt}
                    route.append(route_member)
                    route_hash = hash(tuple(frozenset(item.items()) for item in route))
                    # route_id = (target_hash, route_hash)
                    # debug_route_member = {"name":self.name,"len_route":len(route)}
                    # debug_route = list(data['debug_route'])
                    # debug_route.append(debug_route_member)
                    
                    self.store_hash[route[len(route)-1].get("hash")] = last_ip
                    my_ip = (self.ip,self.port)
                    # print(">>",my_ip)
                    # for ip, _ in self.neighbors.items():
                    #     print(ip)
                    # time.sleep(10)
                    # print(f"{self.name}: Continuing find from",my_ip,"to",route[0].get("hash"),"with salt",salt,"and target hash",target_hash)
                    await self.continue_find(route,hash_to_find=hash_to_find,target=target_hash,salt=salt,my_ip=my_ip)
            except Exception as e:
                print(f"{self.name} find error {e}|{data}")


    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        data_chunks = []

        try:
            while True:
                chunk = await reader.read(1024)
                if not chunk:
                    break
                data_chunks.append(chunk)

            full_data = b''.join(data_chunks)
            decoded = full_data.decode('utf-8')
            json_data = json.loads(decoded)

            await self.handle_conn(json_data, addr, writer)
        
        except json.JSONDecodeError as e:
            print(f"[!]{self.name} JSON decode error: {e}")
        except Exception as e:
            print(f"[!]{self.name} General error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    async def listen(self):
        server = await asyncio.start_server(self.handle_client, '0.0.0.0', self.port)
        print(f"[+] Listening forever on port {self.port}...")

        async with server:
            await server.serve_forever()


BASE_PORT = 20000
NUM_NODES = 200
NEIGHBOR_COUNT = 5  # Or 50 if needed
def find_all_paths(nodes,start_node, target_name, max_paths=500):
    paths = []
    visited = set()

    def dfs(current_node, path, visited_set):
        if current_node.name == target_name:
            paths.append(path[:])
            return
        if len(paths) >= max_paths:
            return
        for (ip, _), _ in current_node.neighbors.items():
            next_node = next((n for n in nodes if n.port == ip[1]), None)
            if next_node and next_node.name not in visited_set:
                visited_set.add(next_node.name)
                path.append(next_node.name)
                dfs(next_node, path, visited_set)
                path.pop()
                visited_set.remove(next_node.name)

    dfs(start_node, [start_node.name], {start_node.name})
    return paths
async def main():
    nodes = []
    ports = list(range(BASE_PORT, BASE_PORT + NUM_NODES))
    addresses = [("127.0.0.1", port) for port in ports]
    assert len(ports) == len(set(ports)), "Duplicate ports detected!"

    # Create nodes with bootstrap neighbors
    for i, port in enumerate(ports):
        name = f"Node{i}"
        bootstrap_candidates = [addr for j, addr in enumerate(addresses) if j != i]
        bootstrap_ips = random.sample(bootstrap_candidates, NEIGHBOR_COUNT)
        node = NetNode(name=name, port=port, bootstrap_ips=bootstrap_ips)
        nodes.append(node)

    # Populate reverse neighbor connections
    for node in nodes:
        for ip, _ in node.neighbors.items():
            for other_node in nodes:
                if ('127.0.0.1', other_node.port) == ip:
                    if ('127.0.0.1', node.port) not in other_node.neighbors:
                        other_node.neighbors[('127.0.0.1', node.port)] = None

    # Start listeners using asyncio.gather
    listen_tasks = [asyncio.create_task(node.listen()) for node in nodes]
    # await asyncio.gather(*listen_tasks)
    print("[+] All nodes launched and listening.")

    await asyncio.sleep(2)  # Give time for servers to bind
    # search_node = random.choice(nodes)
    # target_name = random.choice([n.name for n in nodes])
    # await search_node.start_find(target_name, "SALT")
    # print(f"\n[*] Tracing search paths from {search_node.name} to {target_name}...\n")
    # paths = find_all_paths(nodes,search_node, target_name)
    # if not paths:
    #     print("[-] No paths found.")
    # else:
    #     for i, path in enumerate(paths):
    #         print(f"[+] Path {i + 1}: {' -> '.join(path)}")
    

    # search_node.start_find("Node120","SALT")
    # Build network (make build_network async or wrap with to_thread)
    # await asyncio.gather(*(asyncio.to_thread(node.build_network) for node in nodes))

    # await asyncio.sleep(2)

    # Neighbor diagnostics
    neighbor_map = {}
    for node in nodes:
        neighbor_names = []
        for ip, _ in node.neighbors.items():
            for n in nodes:
                if n.port == ip[1]:
                    neighbor_names.append(n.name)
        neighbor_map[node.name] = neighbor_names
    await asyncio.gather(*listen_tasks)
    # Wait forever
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("[*] Shutting down.")

# Start the full async launcher
if __name__ == "__main__":
    asyncio.run(main())


        