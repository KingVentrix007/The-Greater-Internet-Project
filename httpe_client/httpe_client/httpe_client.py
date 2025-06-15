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
VERSION = 1.0
VERSION_STR = f"VERSION:HTTPE/{VERSION}"



# Singleton-style wrapper
class HttpeClient:
    _client_instance = None

    def __init__(self, **kwargs):
        self._kwargs = kwargs
        self._client = None

    async def init(self):
        if not HttpeClient._client_instance:
            HttpeClient._client_instance = HttpeClientCore(**self._kwargs)
        self._client = HttpeClient._client_instance

    async def start(self):
        if self._client is None:
            await self.init()
        await self._client.start()

    async def send_request(self, method, location, body=None):
        if self._client is None:
            await self.init()
        return await self._client.send_request(method, location, body=body)


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

    def __init__(self, host="127.0.0.1", port=8080,connect_to_edoi=False,edoi_port=None,edoi_ip=None,edoi_client_name = None,edoi_target=None,debug_mode=False,silent_mode=False, pem_path=None, pubkey=None, cert=None, token=None):
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
        self.persistent = False
        self._shutdown_event = threading.Event()
        self.running = False
        self._debug_mode = debug_mode
        self._silent_mode = silent_mode
    async def start(self):
        if self.use_edoi:
            asyncio.create_task(self.listen_for_message())
            await asyncio.sleep(1.5)  # give time for listener to actually bind
            await self._send_connect_async()
            await asyncio.sleep(0.5)
            await self.get_edoi_server_path_async()
            await asyncio.sleep(1)
        await self._init_connection()

    def compute_hashed_identity(self,name:str, salt: str) -> str:

        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    async def choose_path(self):
            # print("Choose path")
            while (self.edoi_path is None):
                await asyncio.sleep(0.1)  # wait for the path to be set
            return self.edoi_path 
            
    async def handle_edoi_conn(self, data):
        edoi_conn_timer_start = time.time()
        edoi_packet_type = data.get("type", None)
        sub_type = data.get("sub_type", "default")
        # print(edoi_packet_type, "EDOI packet type")

        if edoi_packet_type == "path":
            await self._handle_path_packet(data, sub_type)
        elif edoi_packet_type == "return":
            await self._handle_return_packet(data)
        elif edoi_packet_type == "find":
            await self._handle_find_packet(data)
        else:
            if(self._silent_mode == False):
                print("Unknown EDOI packet type received: ", edoi_packet_type)
        edoi_conn_timer_end = time.time()
        if(self._debug_mode == True):
            print("Client:Time to handle edoi packet: ", edoi_conn_timer_end - edoi_conn_timer_start)

    async def _handle_path_packet(self, data, sub_type):
        if sub_type == "default":
            route = data.get("route", None)
            if self.edoi_path is None:
                self.edoi_path = route
                self.all_edoi_paths.append(route)
            else:
                self.all_edoi_paths.append(route)
        elif sub_type == "no_path":
            self.no_path_res_count += 1
            if self.no_path_res_count > 5 and self.edoi_path is None:
                print("No path found for target. Please try again later. EDOI target:", self.edoi_target)

    async def _handle_return_packet(self, data):
        if(self._debug_mode == True):
            with open("../run_output.log", "a") as file:
                file.write(f"Client:Return:{time.time()}\n")
        payload = data.get("payload", None)
        self.edoi_res = payload
        self._got_edoi_event.set()

    async def _handle_find_packet(self, data):
        # print("in find")
        target_hash = data["hash"]
        route = data["route"]
        end_node = route[-1]
        end_node_hash = end_node["hash"]

        if target_hash == end_node_hash:
            print("I really don't know what to do now. EDOI target hash:", target_hash)

        salt = data["salt"]
        my_hash = self.compute_hashed_identity(self.name, salt)
        if my_hash == target_hash:
            print("This shouldn't happen. Clients Cannot be targets. EDOI target hash:", target_hash)
            

        # print(data["hash"], "EDOI target hash. Sending back path:")


    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        start_time = asyncio.get_event_loop().time()
        addr = writer.get_extra_info('peername')
        # print("hello from", addr, "handling connection...")
        try:
            # Read until newline
            data = await reader.read(-1) 
            decoded = data.decode('utf-8').strip()
            json_data = json.loads(decoded)
            if(self._silent_mode == False):
                print(f"[+] Received data from {addr}: {json_data}")
            await self.handle_edoi_conn(json_data)

        except asyncio.IncompleteReadError:
            print(f"[!] Incomplete read from {addr}")
        except json.JSONDecodeError as e:
            print(f"[!] JSON decode error: {e}")
        except Exception as e:
            print(f"[!] General error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            end_time = asyncio.get_event_loop().time()
            if(self._debug_mode == True):
                print(f"[DEBUG] Time to handle connection: {end_time - start_time:.6f} seconds")

    async def listen_for_message(self):
        server = await asyncio.start_server(self.handle_connection, '127.0.0.1', self.port)
        print(f"[+] Async listener running on port {self.port}...")

        async with server:
            await server.serve_forever()
    async def _send_connect_async(self):
        """Connect to the EDOI server and send a connection message."""
        if(self._silent_mode == False):
            print("Connecting to EDOI server at {}:{}".format(self.edoi_ip, self.edoi_port))
        _, writer = await asyncio.open_connection(self.edoi_ip, self.edoi_port)
        message = json.dumps({"type": "connect", "tup": (self.host, self.port)}).encode('utf-8')
        writer.write(message)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def get_edoi_server_path_async(self):
        if(self._silent_mode == False):
            print("Getting EDOI server path asynchronously...")
        _, writer = await asyncio.open_connection(self.edoi_ip, self.edoi_port)
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
        if(self._silent_mode == False):
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
        if(self._silent_mode == False):
            print(f"Sending ENC packet to EDOI server. Method: {method}, Location: {location}")
        if not isinstance(body, str):
            raise TypeError(f"Body must be of type str, current type is {type(body)}")

        headers = self._prepare_headers(headers)
        request_str = self._construct_request_string(method, location, headers, body)
        if request_str is None:
            return None

        encrypted = self._encrypt_packet(request_str)
        if encrypted is None:
            return None

        try:
            send_start = time.time()
            if self.use_edoi:
                if(self._debug_mode):
                    print("[DEBUG]:Client:Sending packet to EDOI server")
                await self.edoi_send_to_target(encrypted)
                response = await self._receive_full_response(None)
                
            else:
                response = self._send_directly(encrypted)
            send_end = time.time()
            if self._debug_mode:
                print(f"[DEBUG]:Client:Time to send packet: {send_end - send_start}")
        except Exception as e:
            print(f"_send_request_enc send error {e}")
            return None

        return self._process_response(response)

    def _prepare_headers(self, headers):
        headers = headers or {}
        headers.setdefault("client_id", str(self._client_id))
        headers.setdefault("packet_id", str(uuid.uuid4()))
        headers.setdefault("is_com_setup", False)
        headers.setdefault("timestamp", datetime.now(timezone.utc))
        headers.setdefault("compressions", "false")
        return headers

    def _construct_request_string(self, method, location, headers, body):
        try:
            lines = [f"METHOD:{method.upper()}", f"LOCATION:{location}", "HEADERS:"]
            lines += [f"{k}:{v}" for k, v in headers.items()]
            lines.append("END")
            if method.upper() == "POST":
                lines.append(body)
                lines.append("END")
            return "\n".join(lines)
        except Exception as e:
            print(f"_send_request_enc plain_text error {e}")
            return None

    def _encrypt_packet(self, plain_request):
        try:
            start = time.time()
            encrypted = self._fernet_class.encrypt(plain_request.encode("utf-8"))
            end = time.time()
            if self._debug_mode:
                print(f"[DEBUG]:Client:Time to encrypt packet: {end - start}")
            return "\n".join([
                f"{VERSION_STR}",
                "TYPE:REQ_ENC",
                f"TOKEN:{self._token}",
                encrypted.decode() if isinstance(encrypted, bytes) else encrypted,
                "END"
            ])
        except Exception as e:
            print(f"enc_request error {e}")
            return None

    def _send_directly(self, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(data.encode())
            return self._receive_full_response(s)

    def _process_response(self, response):
        res = HttpeResponse(response)
        try:
            start = time.time()
            decrypted_body = self._fernet_class.decrypt(res.body()).decode()
            end = time.time()
            if self._debug_mode:
                print(f"[DEBUG]:Client:Time to decrypt packet: {end - start}")
            res._set_body(decrypted_body)
            return res
        except Exception as e:
            print(f"Error in decrypted_body {e}")
            return None

    async def _receive_full_response(self,s) -> str:
        if(self.use_edoi == True):
            if(self._silent_mode == False):
                print("Waiting for EDOI response...")
            await self._got_edoi_event.wait()
            if(self._silent_mode == False):
                print("Received EDOI event, processing response...")
            self._got_edoi_event.clear()

            return self.edoi_res
        else:
            # pass
            response = b""
            while True:
                part = s.recv(4096)  # Receive in chunks (4096 bytes is a common size)
                if not part:
                    break  # No more data, connection closed by server
                response += part
            return response.decode('utf-8')
            

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
                return HttpeResponse("ERROR: Connection failed")
        else:
            await self.edoi_send_to_target(request_data)
            if(self._silent_mode == False):
                print("Connection send completed, waiting for response...")
            response = await self._receive_full_response(None)
            return HttpeResponse(response)

    async def _init_connection(self):
        """Initial secure handshake with server"""
        if(self._silent_mode == False):
            print("Initializing secure connection with server...")
        try:
            self._client_id = uuid.uuid4()
            self._fernet_class = httpe_fernet.HttpeFernet()
            self._aes_key = self._fernet_class.get_key()
            self._aes_key =  base64.urlsafe_b64encode(self._aes_key).decode()

            # Step 1: Get RSA public key
            request = "\n".join([
               VERSION_STR,
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
                VERSION_STR,
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
        if(self._debug_mode == True):
            file = open("../run_output.log","a")
            file.write(f"Client:Forward:{for_t}\n")
            file.close()