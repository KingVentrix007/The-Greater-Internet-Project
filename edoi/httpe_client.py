import socket
import uuid
from datetime import datetime, timezone,timedelta
import httpe_secure as sec  # Must have fernet_encrypt, fernet_decrypt, rsa_encrypt_key, encrypt_user_id
import httpe_cert           # Must have verify_cert(cert, host, pem_path, pubkey)
import json
import httpe_fernet
import base64
import threading
from cryptography.hazmat.primitives import hashes

import time
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

class HttpeClient:
    """Custom secure HTTP-like client using symmetric AES and RSA for initial handshake"""

    def __init__(self, host="127.0.0.1", port=8080,connect_to_edoi=False,edoi_port=None,edoi_ip=None,edoi_client_name = None,edoi_target=None):
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
        self.edoi_target = edoi_target
        self.salt = 'Fixed_SALT'#os.urandom(32).encode("latin-1")
        self.edoi_res = None
        self.got_edoi_res = False
        self.handle_con_in_use = False
        if(self.use_edoi == True):
            threading.Thread(target=self.listen_for_message, daemon=True).start()
            self._send_connect()
            time.sleep(2)
            self.get_edoi_server_path()
            time.sleep(2)
            self._init_connection()
            
    def compute_hashed_identity(self,name:str, salt: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    def get_edoi_server_path(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((self.edoi_ip, self.edoi_port))
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
            "my_ip":('127.0.0.1',self.port)
        }
            client_socket.sendall(json.dumps(packet).encode())

    def handle_edoi_conn(self,data):
        # print(data)
        edoi_packet_type = data.get("type",None)
        sub_type = data.get("sub_type","default")
        if(edoi_packet_type == "path" and self.edoi_path == None):
            if(sub_type == "default"):
                # print("Hello")
                route = data.get("route",None)
                self.edoi_path = route
                
                print("Found path")
        elif(edoi_packet_type == "return"):
            payload = data["payload"]
            # print("Message: ",payload)
            self.edoi_res = payload
            self.got_edoi_res = True
    def listen_for_message(self):

        # Listens for incoming messages on the specified port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', self.port))
                server_socket.listen()
                print(f"[+] Listening forever on port {self.port}...")

                while True:
                    conn, addr = server_socket.accept()
                    with conn:
                        print(f"[+] Connection from {addr}")

                        data_chunks = []
                        while True:
                            chunk = conn.recv(1024)
                            
                            if not chunk:
                                print("Got here")
                                break  # Connection closed by client
                            # print("Chunk: ",chunk)
                            data_chunks.append(chunk)

                        full_data = b''.join(data_chunks)
                        try:
                            decoded = full_data.decode('utf-8')
                            # print(f"[>] Full raw data: {decoded}")

                            json_data = json.loads(decoded)
                            # print(f"[√] Received JSON: {json_data}")
                            # in_ip,in_port = addr
                            # neighbors[addr] = None
                            # threading.Thread(target=self.handle_edoi_conn,args=(json_data,), daemon=True).start()
                            self.handle_edoi_conn(json_data)
                                
                            
                            # print(f"[√] Received JSON: {json_data}")
                        except json.JSONDecodeError as e:
                            print(f"[!]JSON decode error: {e}")
                        except Exception as e:
                            print(f"[!]General error: {e}")
                        finally:
                            pass
                            print("[*] Connection closed.\n")
    def _send_connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((self.edoi_ip, self.edoi_port))
            print(f"[+] Connected to EDOI node at {self.edoi_ip}:{self.edoi_port}")

            # Send a message to the EDOI node
            message = json.dumps({"type": "connect","tup":(self.host,self.port)}).encode('utf-8')
            client_socket.sendall(message)
    def send_request(self, method, location, headers=None, body="", use_httpe=True):
        """Send an encrypted request to the server, establishing connection if needed"""
        try:
            if not self.secure and use_httpe:

                print("Is connecting")
                
            return self._send_request_enc(method, location, headers, body)
        except Exception as e:
            print(f"Error in send_request: {e}")
            return None

    def _send_request_enc(self, method, location, headers=None, body=""):
        print(type(body),"|",type(""))
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
            print("httpe_client_packet_id: ",headers.get("packet_id"))
            if method.upper() == "POST":
                request_lines.append(body)
                request_lines.append("END")
            # print(request_lines)
            try:
                plain_request = "\n".join(request_lines)
            except Exception as e:
                print(f"_send_request_enc plain_text error {e}")
            # enc_request = sec.fernet_encrypt(plain_request, self._aes_key)
            try:
                enc_request = self._fernet_class.encrypt(plain_request.encode("utf-8"))
            except Exception as e:
                print(f"enc_request error {e}")
            print("type(self._token): ",type(self._token))
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
            try:
                if(self.use_edoi == False):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((self.host, self.port))
                        s.sendall(full_data.encode())
                        response = self._receive_full_response(s)
                else:
                    self.edoi_send_to_target(full_data)
                    response = self._receive_full_response(None)

                    print("Use EDOI")
            except Exception as e:
                print(f"_send_request_enc send error {e}")

            res = HttpeResponse(response)
            # decrypted_body = sec.fernet_decrypt(res.body(), self._aes_key)
            # print(res.body())
            # print(res.status_code)
            # print(res._body_str)
            try:
                print("res.body(): ",res.body())
                decrypted_body = self._fernet_class.decrypt(res.body()).decode()
            except Exception as e:
                print(f"Error in decrypted_body {e}")
            res._set_body(decrypted_body)
            return res
        except Exception as e:
            print(f"Error in _send_request_enc: {e}")
            return None
    def edoi_send_to_target(self,payload):
        count = 1
        packet = {
            "type": "forward",
            "route": self.edoi_path,
            "count": count,
            "payload": payload
        }
        # Send to next hop
        # next_hop = route[count]
        # print("Next hop",next_hop)
        time.sleep(1)
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((self.edoi_ip, self.edoi_port)) #! Look here
            # print(f"[+] Sending to EDOI node at {server_ip}:{server_port}")

            # Send a message to the EDOI node
            message = json.dumps(packet).encode('utf-8')
            client_socket.sendall(message)
    def _receive_full_response(self, s: socket.socket) -> str:
        if(self.use_edoi == False):
            """Receives full data from socket"""
            try:
                chunks = []
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b''.join(chunks).decode()
            except Exception as e:
                raise ConnectionError(f"Error receiving data: {e}")
        else:
            while self.got_edoi_res == False:
                pass
            ret_data = self.edoi_res
            self.got_edoi_res = False
            return ret_data

    def _connection_send(self, request_data: str) -> HttpeResponse:
        """Sends a raw request and returns parsed response"""
        if(self.use_edoi == False):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((self.host, self.port))
                    s.sendall(request_data.encode())
                    response = self._receive_full_response(s)
                return HttpeResponse(response)
            except Exception as e:
                print(f"Connection send failed: {e}")
                return None
        else:
            self.edoi_send_to_target(request_data)
             
            response = self._receive_full_response(None)
            return HttpeResponse(response)

    def _init_connection(self):
        """Initial secure handshake with server"""
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
            rsa_response = self._connection_send(request)
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
            response = self._connection_send(aes_request)

            if not response or not response.ok:
                print("Server rejected AES key sharing.")
                return

            response_data = response.json()
            print("response_data == ",response_data)
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
