import warnings
import threading

import uuid
import socket
import json
import time
import uuid
import asyncio
from datetime import datetime, timezone,timedelta
from cryptography.hazmat.primitives import hashes

class NetNode():
    def __init__(self, name: str,port,bootstrap_ips:list,debug_mode=True):
        self.name = name # The name of this node on the network
        self.id = uuid.uuid4().hex # Unique ID of node
        self.neighbors = {} # List of all neighboring nodes (ip,port) combos, Previously stored RSA keys
        self.neighbors_hash = {} # List of all neighboring nodes hash. 
        self.debug_mode = debug_mode # Flag to indicate debug_mode
        # Initiate all neighbors with IP
        for ip in bootstrap_ips:
            self.neighbors[ip] = None # Stores None: Formally would store RSA Key
        for ip in bootstrap_ips:
            self.neighbors_hash[ip] = None # Stores None: Formally would store RSA Key
        self.port = port # Port this server will listen on
        self.ip = '127.0.0.1' # IP server will listen on
        self.max_neighbors = 5 # Max number of neighbors
        self.seen_messages = set() # Set of all seed messages
        self.store_hash = {} # Stored hash to IP combos per search
        self.store_hash_time = {} # Time for store_hash, used to delete old
        self.handled_paths = set() # Set of all handled path messages
        self.send_lock = False # Lock to disable send to avoid threading error
        self.send_loop_count = 0 # Loop to check for send count, unused in node mode
        self.find_hashes_handled = set() # Set of all hashes already checked
        self.found_hash_routes = set() # Set of all found hash routes, used to avoid duplicates
        self.found_end_route = {} # List of all end routes found
        # Used if node is bas
        self.found_paths = {}
        self.failed_paths = {}

        #Flag to allow other outside nodes to connect
        self.is_connect_node = False
        threading.Thread(target=self.memory_cleaner,daemon=True).start() # Run memory cleaner
        # self.build_neighbors() #! USe this in dev
    def memory_cleaner(self):
        """
        Cleans up memory. Removes unused stored paths and hashes
        """
        while True:
            try:
                # Loop through all stored hashes and there time
                rem_hash_val = []
                for hash_val, time_str in list(self.store_hash_time.items()):
                    try:
                        timestamp = datetime.fromisoformat(time_str)
                    except ValueError:
                        print(f"[WARN] Invalid ISO time string: {time_str}")
                        continue
                    now = datetime.now(timezone.utc)
                    if now - timestamp > timedelta(hours=3): # Check if hash is old
                        rem_hash_val.append(hash_val)
                for i in rem_hash_val: # loop though hashes to delete
                    self.store_hash.pop(i, None) # Remove hash
                    self.store_hash_time.pop(i, None) # Remove hash time
            except Exception as e:
                print("[ERROR] Memory cleaner exception:", e)
            time.sleep(1) # Delay for non-blocking code
    async def build_neighbors(self):
        """
        build_neighbors
        Connect to neighboring nodes to build connections
        Untested in prod. Doesn't run well on LAN
        """
        self.neighbors_tmp = set() # Create temporary set to store neighbors
        for ip,key in self.neighbors.items(): # Loop through current neighbors
            self.neighbors_tmp.add(ip) # store IP,PORT in temporary set
        for ip in self.neighbors_tmp: # Loop through temporary set
            tup = (self.ip,self.port) # Create tuple of IP,PORT
            packet = {"type":"neighbors","ip_key":tup}# Create packet
            ret = await self.send_data(packet,addr=ip,init_con=True)# Send packet
            if(ret == False): # Check for ret error
                asyncio.sleep(1) # Wait
    
    def compute_hashed_identity(self, salt: str) -> str:
        """
        Create SHA256 hash of self.name using salt
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update((self.name + salt).encode())
        return digest.finalize().hex()
    def ask_for_hash(self,salt):
        warnings.warn("ask_for_hash is no longer used.",category=DeprecationWarning,stacklevel=2)
        packet = {"type":"hash_req","salt":salt} # Create packet
        json_str = json.dumps(packet)# Convert packet to json
        encoded = json_str.encode('utf-8') 
        # Loop through IP,PORT tuple and send
        for ip, _ in self.neighbors.items(): 
            host, port = ip # Convert from tuple to separate values
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((host, port))
                client_socket.sendall(encoded)
            time.sleep(0.05)# Delay to prevent blocking
    def log_hashes(self,ip,packet):
        warnings.warn("log_hashes is no longer used.",category=DeprecationWarning,stacklevel=2)
        n_hash = packet["hash"]
        n_salt = packet["salt"]
        key = (n_salt, ip)
        self.neighbors_hash[key] = n_hash
    def post_packet(self,packet,target_name,salt):
        warnings.warn("log_hashes is no longer used.",category=DeprecationWarning,stacklevel=2)
        target_hash = self.start_find(target_name,salt)
        path = self.found_paths.get(target_hash,None)
        
        while path == None:
            failed_trys = self.failed_paths.get(target_hash,0)
            if failed_trys >= 10:
                print("Failed to find path after multiple attempts.")
                return False
            time.sleep(0.05)
            path = self.found_paths.get(target_hash,None)
        self.failed_paths[target_hash] = 0
        self.send_to_target(path,packet)
    async def send_data(self, data, addr=None, conn=None, debug_node_name=None, init_con=False):
        """
        Send data

        Args:
        data(str): Data to send
        addr((ip,port)): Address to send data to.
        conn(None): Unused debug value
        debug_node_name(str/None): Name to help identify witch protocol caused exception
        init_conn(bool): Used in build neighbors to suppress connection errors
        """
        message_id = data.get("message_id", str(uuid.uuid4())) # Try extract message ID or create new one
        data["message_id"] = message_id # Ensure packet has message IP
        if(addr == None): # Ensure addr is valid
            raise ValueError("addr cannot be none")
        host, port = addr # Extract values from tuple (ip,port)
        try:
            # Convert to json
            json_str = json.dumps(data)+"\n"
            encoded = json_str.encode("utf-8")


            reader, writer = await asyncio.open_connection(host, port) # asyncio reader and writer
            writer.write(encoded) # Send data
            await writer.drain()
            writer.close() # Close writer
            await writer.wait_closed() # non-blocking ensure writer is closed
            # print(f"{`self.name}:Send completed to {host}:{port} with message_id {message_id}")
            return True
        except Exception as e: # General catch all Exception
            print(f"[ERROR]: {self.name}: send_data to {host, port} error")

            return False
   
    async def continue_find(self,route,hash_to_find,debug_route=None,target=None,salt=None,ip_combo=None):
        """
        Continue find request

        Args
        route(list): The current path that has be used
        hash_to_find: Unused
        debug_route: Unused
        Target(str): The hash of the server being searched for
        Salt(str): The salt used to create the hash
        ip_combo(tuple): ip,port of the node sending the continue_find request 
        """

        # Create packet
        packet = {"type":"find","route":route,"hash":target,"salt":salt, "message_id": str(uuid.uuid4()),"ip_combo":ip_combo}
        
        # Insure packet has a message_id value
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        
        # Save time before send
        if(self.debug_mode == True):
            before_send_all = time.time()
        #Loop through ALL neighbors and send packet
        for ip, _ in self.neighbors.items():
            
            ret = await self.send_data(packet,ip,debug_node_name="cont find")
            if(ret != True):
                await asyncio.sleep(1) # Wait if send failed
                await self.send_data(packet,ip,debug_node_name="cont find")
        # Save time after send
        if(self.debug_mode == True):
            after_send_all = time.time()
            #Output debug message
            # print(f"[DEBUG]: {self.name}:Continue:Time to send packets:{after_send_all-before_send_all}")

    async def return_path(self,path,addr=None,debug_node_name=None):
        print(f"{self.name}:Returning path")
        if(addr == None):
            print(f"{self.name}:Bulk sending")
            for ip, _ in self.neighbors.items():
                ret = await self.send_data(path,ip,debug_node_name=f"Scan send: {debug_node_name}")
                if(ret != True):
                    await asyncio.sleep(1) # Wait if send failed
                    await self.send_data(path,ip,debug_node_name=f"Scan send: {debug_node_name}")
        else:
            print(f"{self.name}:Sending to {addr} with debug node name {debug_node_name}")
            ret = await self.send_data(path,addr=addr,debug_node_name=debug_node_name)
            if(ret == False):
                await asyncio.sleep(1) # Wait if send failed
                await self.send_data(path,addr=addr,debug_node_name=debug_node_name)
    async def hash_str(self,name,salt):
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    async def start_find(self, target_name: str, salt: str):
        target_hash = await self.hash_str(target_name, salt)  # FIXED
        my_hash = self.compute_hashed_identity(salt)
        route_member = {"hash": my_hash, "salt": salt}
        route = [route_member]

        packet = {
            "type": "find",
            "route": route,
            "hash": target_hash,
            "salt": salt,
            "message_id": str(uuid.uuid4()),
            "ip_combo":(self.ip,1000+self.port)
        }
        for ip, key in self.neighbors.items():
            await self.send_data(packet,ip,debug_node_name="send packet")
        return target_hash

    async def handle_conn(self,data,addr,conn):
        message_id = data.get("message_id")
        if message_id:
            self.seen_messages.add(message_id)
        if(data["type"] == "get_rsa"):
            key = self.public_key
            key_data = {"key",key}
            await self.send_data(key_data, addr,"rsa get")
        elif(data["type"] == "connect"):
            self.is_connect_node = True
            ip_port_combo = tuple(data.get("tup"))
            self.neighbors[ip_port_combo] = None
            print(f"Object connected to {self.name} at {ip_port_combo}")
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
                await asyncio.sleep(0.05)
            except Exception as e:
                pass
        elif(data["type"] == "hash_res"):
            self.log_hashes(addr,data)
        elif data['type'] == "return":
            
            
            try:
                got_return_packet_time = time.time()
                route = data["route"]
                count = int(data["count"])
                payload = data["payload"]
                my_hash = self.compute_hashed_identity(route[count]["salt"])
                print(f"{self.name}:Got return packet")
                if my_hash == route[count]["hash"]:
                    print(f"{self.name}:Return:{time.time()}")
                    past_hash = route[count + 1]["hash"]
                    if past_hash == my_hash:
                        print("[ERROR]. Previous node matches current node")
                        return  # Ignore if the hash matches the previous one
                    else:
                        ip_combo = data.get("ip_combo",None)
                        if(ip_combo != None):
                            self.store_hash[past_hash]  = ip_combo
                    if count > 0:
                        combo = (self.ip,1000+self.port)
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
                            # print(f"{self.name}:Calling send_data for return at {time.time()}")
                            ret = await self.send_data(next_packet, val,debug_node_name="return",conn=got_return_packet_time)
                            if(ret != True):
                                await asyncio.sleep(1)  # Wait if send failed
                                print(f"{self.name}:Retrying send_data for return at {time.time()}")
                                await self.send_data(next_packet, val,debug_node_name="return",conn=got_return_packet_time)
                            # print(f"{self.name}:Call send data ended at {time.time()}")
                        else:
                            print(f"{self.name}:Bulking return")
                            for ip, _ in self.neighbors.items():
                                await self.send_data(next_packet, ip,"type return")
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
                    # print(f"{self.name}:Forward:{time.time()}")
                    if count + 1 < len(route):
                        next_packet = {
                            "type": "forward",
                            "route": route,
                            "count": count + 1,
                            "payload": payload,
                            "ip_combo": (self.ip, 1000+self.port)
                        
                        }
                        if(self.store_hash.get(route[count+1].get("hash"),None) != None):
                            self.store_hash_time[route[count+1]["hash"]] = datetime.now(timezone.utc).isoformat()
                            next_ip = tuple(self.store_hash.get(route[count+1]["hash"]))
                            await self.send_data(next_packet, next_ip,debug_node_name="forward",conn=got_forward_packet_start)
                        else:
                            # print("[!] No stored hash found for next hop, bulk sending forward packet.")
                            bulk_start_time = time.time()
                            for ip, _ in self.neighbors.items():
                                await self.send_data(next_packet, ip,debug_node_name="forward",conn=got_forward_packet_start)
                            bulk_end_time = time.time()
                            print(f"Sending bulk message delay {bulk_end_time-bulk_start_time}")
                    else:
                        print(f"[🎯] {self.name} received payload: {payload}")
                        # await self.return_to_sender(route, f"ACK from {self.name}")
            except Exception as e:
                print(f"[!] {self.name}Forward error: {e}")

        elif data["type"] == "path":
            
            message_id = data["message_id"]
            if(message_id in self.handled_paths):
                print(f"ignored")
                return
            self.handled_paths.add(message_id)
            try:                
                count = int(data["count"])
                route = data['route']
                my_member = route[count]
                try:
                    my_hash = self.compute_hashed_identity(my_member["salt"])
                except Exception as e:
                    print(f"Hashing error {e}")
                if my_hash == my_member["hash"]:
                    if count > 0:
                        data['count'] = count - 1
                        that_hash = route[data['count']]["hash"]
                        if(my_hash == that_hash):
                            that_hash = route[count-1]["hash"]
                            data['count'] = count - 2
                        end_hash = route[len(route)-1]["hash"]
                        if(that_hash == end_hash):
                            print("This shouldn't happen")
                        # 

                        if(self.store_hash.get(that_hash,None) != None):
                            self.store_hash_time[that_hash] = datetime.now(timezone.utc).isoformat()

                            val = tuple(self.store_hash.get(that_hash,None))
                            if(val == None):
                                print("Error")
                            await self.return_path(data,val)
                        else:
                            await self.return_path(data,debug_node_name="other loop")
                    else:
                        sub_type = data.get("sub_type","default")
                        if(sub_type == "default"):
                            print(f"{self.name}: Back at main")
                            try:
                                end_hash = route[len(route)-1]
                            except Exception as e:
                                print(f"End hash error {e}")
                            try:
                                self.found_paths[end_hash.get("hash",None)] = route
                            except Exception as e:
                                print(f"Logging found error {e}")
                        else:
                            try:
                                end_hash = route[len(route)-1]
                            except Exception as e:
                                print(f"End hash error {e}")
                            try:
                                inc = int(self.failed_paths.get(data.get("hash",None),0))
                                inc+=1
                                self.failed_paths[data.get("hash",None)] = inc
                            except Exception as e:
                                print(f"Logging found error {e}")

                else:
                    return
                    # print(f"{self.name}: Hash mismatch in path backtracking")

            except Exception as e:
                print(f"{self.name} Path error: {e}")
        elif(data['type'] == "find"):
            try:
                
                target_hash = data["hash"]
                route = list(data['route'])
                route_hash = hash(tuple(frozenset(item.items()) for item in route))
                route_hashes = list(item.get("hash") for item in route)
                route_id = (target_hash, route_hash)
                try:
                    if(route in self.found_end_route.get(route_id,None)):
                        print(f"{self.name}: Route already found, ignoring.")
                        return
                except Exception as e:
                    pass
                if(target_hash in self.find_hashes_handled):
                    if(target_hash == route[len(route)-1].get("hash")):
                        print(route)
                    # print(f"{self.name}:Handled find hash already, ignoring. Hash") 
                    return
                self.find_hashes_handled.add(target_hash)
                last_ip = data.get("ip_combo",None)
                self.store_hash[route[len(route)-1].get("hash")] = last_ip
                self.store_hash_time[route[len(route)-1].get("hash")] = datetime.now(timezone.utc).isoformat()
                hash_to_find = target_hash
                salt = data["salt"]
                my_hash = self.compute_hashed_identity(salt)
                # print(f"{self.name}:len(route):{len(route)}")
                if(len(route) >= 8):
                    print(f"{self.name}: No more than 8 hops allowed, ignoring request. Route: ", route)
                    route_member = {"hash":my_hash,"salt":salt}
                    message_id = data.get("message_id",None)
                    ret_data = {"type":"path","sub_type":"no_path","hash":target_hash,"salt": salt,"route":route,"count":len(route)-1}
                    that_hash = route[int(ret_data["count"])]["hash"]

                    

                    if(self.store_hash.get(that_hash,None) != None):
                        self.store_hash_time[that_hash] = datetime.now(timezone.utc).isoformat()
                        val = tuple(self.store_hash.get(that_hash,None))
                        if(val == None):
                            print("Error")
                        await self.return_path(ret_data,val)
                    else:
                        print("No match")
                elif(my_hash == hash_to_find):
                    print("Found Match")
                    route_member = {"hash":my_hash,"salt":salt}
                    route.append(route_member)
                    ret_data = {"type":"path","route":route,"count":len(route)-2,"hash":target_hash,"salt":salt}
                    ret_data["message_id"] = str(uuid.uuid4())
                    that_hash = route[int(ret_data["count"])]["hash"]
                    if(self.store_hash.get(that_hash,None) != None):
                        self.store_hash_time[that_hash] = datetime.now(timezone.utc).isoformat()
                        val = tuple(self.store_hash.get(that_hash,None))
                        if(val == None):
                            print("Error: No value found for that hash")
                            await self.return_path(ret_data,debug_node_name="other run")
                        await self.return_path(ret_data,val)
                    else:
                        print("No match")
                        await self.return_path(ret_data,debug_node_name="other run")
                elif my_hash not in route_hashes:
                    route_member = {"hash":my_hash,"salt":salt}
                    route.append(route_member)
                    route_hash = hash(tuple(frozenset(item.items()) for item in route))
                    self.store_hash[route[len(route)-1].get("hash")] = last_ip
                    ip_combo = (self.ip,1000+self.port)
                    await self.continue_find(route,hash_to_find=hash_to_find,target=target_hash,salt=salt,ip_combo=ip_combo)
                else:
                    route_member = {"hash":my_hash,"salt":salt}
                    route.append(route_member)
                    route_hash = hash(tuple(frozenset(item.items()) for item in route))
                    self.store_hash[route[len(route)-1].get("hash")] = last_ip
                    ip_combo = (self.ip,1000+self.port)
                    await self.continue_find(route,hash_to_find=hash_to_find,target=target_hash,salt=salt,ip_combo=ip_combo)
                    # print("Not really sure what to do here, but ignoring. Hash: ", my_hash, " Route: ", route)
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
            print(f"[!]{self.name} JSON decode error: {e}:{full_data}")
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



