import os
import socket
import uuid
from datetime import datetime, timezone,timedelta
import httpe_core.httpe_secure as sec  # Must have fernet_encrypt, fernet_decrypt, rsa_encrypt_key, encrypt_user_id
import httpe_core.httpe_cert as httpe_cert           # Must have verify_cert(cert, host, pem_path, pubkey)
import json
import httpe_core.httpe_fernet as httpe_fernet
import httpe_core.httpe_logging as httpe_logging
import base64
import threading
from cryptography.hazmat.primitives import hashes
import asyncio
import time



# Singleton-style wrapper
class Httpe:
    _client_instance = None

    def __init__(self, **kwargs):
        if not Httpe._client_instance:
            Httpe._client_instance = HttpeClientCore(**kwargs)

        self._client = Httpe._client_instance

    async def start(self):
        await self._client.start()

    async def send_request(self, method, location, body=None):
        return await self._client.send_request(method, location, body)


class HttpeResponse:
    """Parses HTTPE responses in the format: headers + END + body"""

    def __init__(self, raw_response: str):
        self.raw_response = raw_response.strip()
        self.headers = {}
        self._body_str = ""
        self.status = None
        self.status_code = -1
        self.content_length = -1
        self._parse()

    def _parse(self):
        if "END" not in self.raw_response:
            raise ValueError("Malformed response: missing 'END' delimiter")

        header_section, body_section = self.raw_response.split("END", 1)
        header_lines = header_section.strip().splitlines()
        self._body_str = body_section.strip()

        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                self.headers[key.strip()] = value.strip()

        self.status = self.headers.get("STATUS")

        try:
            self.status_code = int(self.headers.get("STATUS_CODE", -1))
        except (ValueError, TypeError):
            self.status_code = -1

        try:
            self.content_length = int(self.headers.get("CONTENT_LENGTH", -1))
        except (ValueError, TypeError):
            self.content_length = -1

    def _set_body(self, body: str):
        self._body_str = body

    @property
    def text(self) -> str:
        return self._body_str

    @property
    def content(self) -> bytes:
        return self._body_str.encode("utf-8")

    def body(self) -> str:
        return self._body_str

    def json(self) -> dict:
        try:
            return json.loads(self._body_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in response body: {e}")

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def __getitem__(self, key):
        return self.headers.get(key)

    def __repr__(self):
        return f"<HttpeResponse status={self.status} content_length={self.content_length}>"

class HttpeClientCore:
    """Custom secure HTTP-like client using symmetric AES and RSA for initial handshake"""

    def __init__(self, host="127.0.0.1", port=8080,connect_to_edoi=False,edoi_port=None,edoi_ip=None,edoi_client_name = None,edoi_target=None,persistent=False,debug_mode=False):
        """
        Initialize the class.

        Args:
            host (str): IP address to bind the server to. Defaults to "127.0.0.1". In EDOI mode, serves as the ip to listen on for incoming connections.
            port (int): Port number for the server. Defaults to 8080. In EDOI mode, serves as the port to listen on for incoming connections.
            connect_to_edoi (bool): Whether to connect to the EDOI network. Defaults to False.
            edoi_port (int or None): The port to connect to for EDOI. Required if `connect_to_edoi` is True.
            edoi_ip (str or None): The IP address of the EDOI node to connect to.
            edoi_client_name (str or None): The client's identifier within the EDOI network.
            edoi_target (str or None): The intended destination or service within EDOI to connect to.
        """
        self.host = host
        self.port = port
        self._client_id = None
        self._aes_key = None
        self._server_rsa_pub_key = None
        self._aes_key_enc = None
        self._user_id_enc = None
        self._enc_mode_active = False
        self.secure = False
        self._token = None

        #EDOI stuff
        self.edoi_port = edoi_port
        self.edoi_ip = edoi_ip
        self.name = edoi_client_name or uuid.uuid4()
        self.use_edoi = connect_to_edoi
        self.edoi_path = None
        self.all_edoi_paths = []
        self.no_path_res_count = 0 # Counts how many times we got no path response from the EDOI server
        self.edoi_target = edoi_target
        self.salt = os.urandom(32).hex()
        self.edoi_res = None
        self.got_edoi_res = False
        self._got_edoi_event = asyncio.Event()
        self.handle_con_in_use = False
        self.persistent = persistent
        self._shutdown_event = threading.Event()
        self.running = False
        self._debug_mode = debug_mode
    async def start(self):
        if self.use_edoi:
            server_task = asyncio.create_task(self.listen_for_message())
            await asyncio.sleep(1.5)  # give time for listener to actually bind
            await self._send_connect_async()
            await asyncio.sleep(0.5)
            await self.get_edoi_server_path_async()
            await asyncio.sleep(1)
        await self._init_connection()

    def compute_hashed_identity(self,name:str, salt: str) -> str:
        # return name

        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    async def choose_path(self):
            while (self.edoi_path is None):
                await asyncio.sleep(0.1)  # wait for the path to be set
            return self.edoi_path  # or raise an exception / handle as needed

        # # Find the path with the fewest nodes (i.e., shortest path)
        # shortest_path = min(self.all_edoi_paths, key=len)
        # print("Choosing shortest path with {} nodes.".format(len(shortest_path)) + "\nPath: " + str(shortest_path) + "\n")
        # return shortest_path
            
    async def handle_edoi_conn(self,data):
        edoi_conn_timer_start = time.time()
        # print(data)
        edoi_packet_type = data.get("type",None)
        print(edoi_packet_type, "EDOI packet type")
        sub_type = data.get("sub_type","default")
        if(edoi_packet_type == "path"):
            print("in path")
            if(sub_type == "default"):
                # print("Hello")
                print("Go path")
                # print(data)
                route = data.get("route",None)
                if(self.edoi_path == None):
                    self.edoi_path = route
                    self.all_edoi_paths.append(route)
                    print("Found path")
                else:
                    print("Go new path")
                    self.all_edoi_paths.append(route)
            elif(sub_type == "no_path"):
                
                self.no_path_res_count += 1
                # print("no path")
                if(self.no_path_res_count > 5 and self.edoi_path == None):
                    print("No path found for target. Please try again later. EDOI target: ",self.edoi_target)
        
        elif(edoi_packet_type == "return"):
            # print("return")
            file = open("../run_output.log","a")
            file.write(f"Client:Return:{time.time()}\n")
            file.close()
            payload = data.get("payload",None)
            self.edoi_res = payload
            self._got_edoi_event.set()
        elif(edoi_packet_type == "find"):
            print("in find")
            # print(data["route"], "EDOI route found. Sending path back to EDOI server.")
            target_hash = data['hash']
            route = data["route"]
            end_node = route[-1]
            end_node_hash = end_node['hash']
            if(target_hash == end_node_hash):
                print("I really dont know what to do now. EDOI target hash: ", target_hash)
            salt = data['salt']
            my_hash = self.compute_hashed_identity(self.name,salt)
            if(my_hash == target_hash):
                print("I dont know what to do now")
            print(data['hash']," EDOI target hash. Sending back path: ")
        edoi_conn_timer_end = time.time()
        print("Client:Time to handle edoi packet: ",edoi_conn_timer_end-edoi_conn_timer_start)
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        start_time = asyncio.get_event_loop().time()
        addr = writer.get_extra_info('peername')
        print("hello from", addr, "handling connection...")
        try:
            # data = await reader.readuntil(b"\n")  # Read until newline
            data = await reader.read(-1) 
            decoded = data.decode('utf-8').strip()
            json_data = json.loads(decoded)
            print(f"[+] Received data from {addr}: {json_data}")
            await self.handle_edoi_conn(json_data)

        except asyncio.IncompleteReadError:
            print(f"[!] Incomplete read from {addr}")
        except json.JSONDecodeError as e:
            print("DECODED DATA: \n",decoded)
            print("END OF DECODED DATA\n")
            print(f"[!] JSON decode error: {e}")
        except Exception as e:
            print(f"[!] General error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            end_time = asyncio.get_event_loop().time()
            print(f"[] Time to handle connection: {end_time - start_time:.6f} seconds")

    async def listen_for_message(self):
        server = await asyncio.start_server(self.handle_connection, '127.0.0.1', self.port)
        print(f"[+] Async listener running on port {self.port}...")

        async with server:
            await server.serve_forever()
    async def _send_connect_async(self):
        """Connect to the EDOI server and send a connection message."""
        print("Connecting to EDOI server at {}:{}".format(self.edoi_ip, self.edoi_port))
        reader, writer = await asyncio.open_connection(self.edoi_ip, self.edoi_port)
        message = json.dumps({"type": "connect", "tup": (self.host, self.port)}).encode('utf-8')
        writer.write(message)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def get_edoi_server_path_async(self):
        print("Getting EDOI server path asynchronously...")
        reader, writer = await asyncio.open_connection(self.edoi_ip, self.edoi_port)
        client_hash = self.compute_hashed_identity(self.name,self.salt)
        target_hash = self.compute_hashed_identity(self.edoi_target,self.salt)
        route_member = {"hash": client_hash, "salt": self.salt}
        route = [route_member]
        packet = {
        "type": "find",
        "route": route,
        "hash": target_hash,
        "salt": self.salt,
        # "key": self.public_key.public_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PublicFormat.SubjectPublicKeyInfo
        # ).decode(),
        
        "message_id": str(uuid.uuid4()),
        "ip_combo":('127.0.0.1',self.port)
    }
        writer.write(json.dumps(packet).encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print("Sent path request to EDOI server. Waiting for response...")
    async def send_request(self, method, location, headers=None, body="", use_httpe=True):
        """Send an encrypted request to the server, establishing connection if needed"""
        try:
            if not self.secure and use_httpe:

                print("Is connecting")
                
            return await self._send_request_enc(method, location, headers, body)
        except Exception as e:
            print(f"Error in send_request: {e}")
            return None

    async def _send_request_enc(self, method, location, headers=None, body=""):
        print("Sending ENC packet to EDOI server. Method: {}, Location: {}".format(method, location))
        if(type(body) != type("")):
            raise TypeError(f"Body must be of type str, current type is {type(body)}")
        """Send an encrypted packet after key exchange"""
        if headers is None:
            headers = {}

        try:
            try:
                headers.setdefault("client_id", str(self._client_id))
                headers.setdefault("packet_id", str(uuid.uuid4()))
                headers.setdefault("is_com_setup", False)
                headers.setdefault("timestamp", datetime.now(timezone.utc))
                headers.setdefault("compressions", "false")

                request_lines = [f"METHOD:{method.upper()}", f"LOCATION:{str(location)}", "HEADERS:"]
                request_lines += [f"{str(k)}:{str(v)}" for k, v in headers.items()]
                request_lines.append("END")
            except Exception as e:
                print(f"Failed in setting headers {e}")
            if method.upper() == "POST":
                request_lines.append(body)
                request_lines.append("END")
            try:
                plain_request = "\n".join(request_lines)
            except Exception as e:
                print(f"_send_request_enc plain_text error {e}")
            try:
                start_encrypt_timer = time.time()
                enc_request = self._fernet_class.encrypt(plain_request.encode("utf-8"))
                end_encrypt_timer = time.time()
                if(self._debug_mode == True):
                    print(f"[DEBUG]:Client:Time to encrypt packet:{end_encrypt_timer-start_encrypt_timer}")
                # print(f"Encryption took {end_enrypt_timer - start_ecrypt_timer} seconds")
            except Exception as e:
                print(f"enc_request error {e}")
                return
            # print("type(self._token): ",type(self._token))
            packet = [
                "VERSION:HTTPE/1.0",
                "TYPE:REQ_ENC",
                f"TOKEN:{self._token}",
                enc_request,
                "END"
            ]
            try:
                full_data = "\n".join(packet)
            except Exception as e:
                print(f"full_data error {e}")
                return
            try:
                send_time_start = time.time()
                if(self.use_edoi == False):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((self.host, self.port))
                        s.sendall(full_data.encode())
                        response = self._receive_full_response(s)
                    send_time_end = time.time()
                    if(self._debug_mode == True):
                        print(f"[DEBUG]:Client:Time to send packet: {send_time_end-send_time_start}")
                else:
                    
                    await self.edoi_send_to_target(full_data)
                    response = await self._receive_full_response(None)
                    send_time_end = time.time()
                    if(self._debug_mode == True):
                        print(f"[DEBUG]:Client:Time to send EDOI-NET packet: {send_time_end-send_time_start}")
            except Exception as e:
                print(f"_send_request_enc send error {e}")

            res = HttpeResponse(response)
            try:
                decrypt_time_start = time.time()
                decrypted_body = self._fernet_class.decrypt(res.body()).decode()
                decrypt_time_end = time.time()
                if(self._debug_mode == True):
                    print("[DEBUG]:Client:Time to decrypt packet", decrypt_time_end - decrypt_time_start, "seconds")
            except Exception as e:
                print(f"Error in decrypted_body {e}")
                return None
            res._set_body(decrypted_body)
            return res
        except Exception as e:
            print(f"Error in _send_request_enc: {e}")
            return None
    async def edoi_send_to_target(self,payload):
        count = 1
        packet = {
            "type": "forward",
            "route": await self.choose_path(),
            "count": count,
            "payload": payload,
            "ip_combo":(self.host,self.port)
        }
        # Send to next hop
        # next_hop = route[count]
        # print("Next hop",next_hop)
        # time.sleep(1)
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        # print(f"Client:Forward:{time.time()}")
        for_t = time.time()
        # httpe_logging.sync_log(f"Client:Forward:{time.time()}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((self.edoi_ip, self.edoi_port)) #! Look here
            # print(f"[+] Sending to EDOI node at {server_ip}:{server_port}")

            # Send a message to the EDOI node
            message = json.dumps(packet).encode('utf-8')
            client_socket.sendall(message)
        file = open("../run_output.log","a")
        file.write(f"Client:Forward:{for_t}\n")
        file.close()
        # print("Packet has been sent at", time.time())
    async def _receive_full_response(self,s) -> str:
        print("Waiting for full response...")
        await self._got_edoi_event.wait()
        print("Received EDOI event, processing response...")
        self._got_edoi_event.clear()
        return self.edoi_res

    async def _connection_send(self, request_data: str) -> HttpeResponse:
        """Sends a raw request and returns parsed response"""
        if(self.use_edoi == False):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((self.host, self.port))
                    s.sendall(request_data.encode())
                    response = await self._receive_full_response(s)
                return HttpeResponse(response)
            except Exception as e:
                print(f"Connection send failed: {e}")
                return None
        else:
            await self.edoi_send_to_target(request_data)
             
            response = await self._receive_full_response(None)
            return HttpeResponse(response)

    async def _init_connection(self):
        """Initial secure handshake with server"""
        print("Initializing secure connection with server...")
        try:
            self._client_id = uuid.uuid4()
            self._fernet_class = httpe_fernet.HttpeFernet()
            self._aes_key = self._fernet_class.get_key()
            self._aes_key =  base64.urlsafe_b64encode(self._aes_key).decode()

            # Step 1: Get RSA public key
            request = "\n".join([
                "VERSION:HTTPE/1.0",
                "TYPE:GET_RSA",
                "METHOD:POST",
                "END"
            ])
            rsa_response = await self._connection_send(request)
            if not rsa_response or not rsa_response.ok:
                print("Failed to retrieve RSA public key from server.")
                return

            json_data = rsa_response.json()
            self._server_rsa_pub_key = json_data.get("rsa")
            if not self._server_rsa_pub_key:
                print("RSA key missing in server response.")
                return

            # Step 2: Send AES key and ID (RSA encrypted)
            enc_aes = sec.rsa_encrypt_key(self._aes_key.encode("utf-8"), self._server_rsa_pub_key)
            enc_user_id = sec.encrypt_user_id(str(self._client_id), self._server_rsa_pub_key)

            request_lines = [
                "VERSION:HTTPE/1.0",
                "TYPE:SHARE_AES",
                "METHOD:POST",
                "HEADERS:",
                f"aes_key:{enc_aes}",
                f"user_id:{enc_user_id}",
                f"packet_id:{str(uuid.uuid4())}",
                f"timestamp:{datetime.now(timezone.utc).isoformat()}",
                "END"
            ]
            aes_request = "\n".join(request_lines)
            response = await self._connection_send(aes_request)

            if not response or not response.ok:
                print("Server rejected AES key sharing.")
                return

            response_data = response.json()
            # print("response_data == ",response_data)
            enc_token = response_data.get("token")
            enc_cert = response_data.get("certificate")

            if not enc_token or not enc_cert:
                print("Missing token or certificate in response.")
                return

            # cert = sec.fernet_decrypt(enc_cert, self._aes_key)
            cert = self._fernet_class.decrypt(enc_cert).decode("utf-8")
            if not httpe_cert.verify_cert(cert, self.host, "public.pem", self._server_rsa_pub_key):
                print("Invalid certificate received from server.")
                return

            self._token = enc_token
            self._aes_key_enc = enc_aes
            self._user_id_enc = enc_user_id
            self._enc_mode_active = True
            self.secure = True

        except Exception as e:
            print(f"Handshake failed: {e}")
    def terminate(self):
        print("Terminating connection to server...")
        self.running = False
        if self.persistent:
            self._shutdown_event.set()
    def _keep_alive(self):
        print("[*] Persistent mode active. Client will stay alive until terminate() is called.")
        while self.running == True:
            time.sleep(1)  # Keep thread alive, avoid busy loop
