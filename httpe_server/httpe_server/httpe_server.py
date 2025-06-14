from cryptography.hazmat.primitives import hashes
import time
import os
import socket
import threading
import inspect
import json
from httpe_core.httpe_class import Response
from datetime import datetime, timezone, timedelta
import httpe_core.httpe_secure as sec
import uuid
import base64
import httpe_core.httpe_fernet as httpe_fernet
import httpe_core.httpe_logging as httpe_logging
import signal
import sys
import logging
import threading

class Httpe:
    def __init__(self,server_host="127.0.0.1",Port=8080,running_version="1.0",crte_file_path="cert.crte",key_dir_path=".",name="edoi node",use_edoi_node=False,edoi_ip=None,edoi_port=None):
        """
        Initialize the class.

        Args:
        server_host(str): IP address to bind the server to. Defaults to "127.0.0.1"
        port(int): Port of the server. Defaults to 8080
        running_version(str): HTTPE version of the server. Defaults to current version
        name(str): Server name when running in EDOI-NET mode.
        crte_file_path(str): File path to certificate. Defaults to cert.crte
        key_dir_path(str): Dir path where the .edoi private and public keys are stored. Defaults to "."
        use_edoi_node(bool): Wether or not to run in EDOI-NET mode. Defaults to False
        edoi_ip(str/None): IP of the EDOI-NET node to connect to
        edoi_port(int/None): Port of the EDOI-NET node to connect to

        """
        self.cert_path = crte_file_path
        self.key_dir_path = key_dir_path
        if(os.path.exists(self.cert_path) == False):
            raise FileNotFoundError("Certificate file not found: cert.crte. Please generate a certificate using the certgen.py script before starting the server.")
        if(os.path.exists(f"{self.key_dir_path}/private_key.edoi") == False or os.path.exists(f"{self.key_dir_path}/public_key.edoi") == False):
            raise FileNotFoundError(".edoi keys files not found. Please generate them using the certgen.py script")

        self.routes = {}
        self.host = server_host
        self.port = Port
        self.valid_token_ids = []
        self.valid_token_ids_per_user = {}
        self._banned_ips = {}
        self.user_keys = {}
        self.rsa_private_key = None
        self.rsa_public_key_shared = None
        self.master_aes_class = httpe_fernet.HttpeFernet()
        self.master_aes_key = self.master_aes_class.get_key()
        self._running = True
        self.cert = None
        self._load_keys()
        self.load_cert()
        self.version = running_version
        # self._log_file = None
        # self._log_file = open("server_log.log","a")
        logging.basicConfig(filename='logfile.log', level=logging.INFO, format='[I]%(asctime)s: %(message)s', datefmt='%Y-%m-%dT%H:%M:%SZ')
        # Used if EDOI node
        self.is_edoi_node = use_edoi_node
        self.name = name
        self.edoi_ip = edoi_ip
        self.edoi_port = edoi_port
        self.edoi_return_routes = {}
        if(self.is_edoi_node == True):
            self._send_connect()
    def _shutdown(self, signum, frame):
        print("\nShutting down HTTPE server...")
        print("[v] Purging users")
        self.user_keys.clear()
        if(len(self.user_keys) > 0):
            print("[!] Failed to purge users")
        print("[v] Purging token ids")
        self.valid_token_ids.clear()
        self.valid_token_ids_per_user.clear()
        if(len(self.valid_token_ids) > 0 or len(self.valid_token_ids_per_user) > 0):
            print("[!] Failed to purge token IDs")
        print("Saving logs")
        # self._log_file.close()
        
        self._running = False
    def _load_keys(self):
        try:
            with open("private_key.edoi","r") as f:
                key_data = json.load(f)
                expire_data = key_data['valid_to']
                timestamp = datetime.fromisoformat(expire_data)
                now = datetime.now(timezone.utc)
                if now - timestamp > timedelta(minutes=20):
                    raise Exception("Private key expired")
                key = key_data["key"]
                self.rsa_private_key = key
            with open("public_key.edoi","r") as f:
                key_data = json.load(f)
                expire_data = key_data['valid_to']
                timestamp = datetime.fromisoformat(expire_data)
                now = datetime.now(timezone.utc)
                if now - timestamp > timedelta(minutes=20):
                    raise Exception("Public key expired")
                key = key_data["key"]
                self.rsa_public_key_shared = key
        except Exception as e:
            self._log_internal_error(e)

            ##print(f"Load keys error {e}")
            raise Exception(e)
        
    def load_cert(self):
        try:
            with open("cert.crte","r") as f:
                self.cert = json.load(f)
        except Exception as e:
            self._log_internal_error(e)

            ##print(f"Load keys error {e}")
            raise Exception(e)
    def path(self, route, method="GET",requires_enc=True):
        def decorator(func):
            self.routes[(route, method)] = func
            return func
        return decorator
    def paths(self):
        for (route, method), func in self.routes.items():
            # enc_status = "Encrypted" if requires_enc else "Unencrypted"
            print(f"{method} {route} ) -> {func.__name__}")
    def serve(self, host="127.0.0.1", port=8080):
        
        print(f"HTTPE server running on {host}:{port}...")
        signal.signal(signal.SIGINT, self._shutdown)  # Handle Ctrl+C
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            s.settimeout(1.0)  # <-- check every 1 second for interrupt

            try:
                while self._running:
                    try:
                        conn, addr = s.accept()
                        threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue  # Allows checking for KeyboardInterrupt
            except KeyboardInterrupt:
                ##print("\nShutting down HTTPE server...")
                return
        
                                # ##print("[*] Connection closed.\n")
    def _create_token(self, user_id):
        
        token = {"user_id":user_id,"session_id":str(uuid.uuid4()),"timestamp":datetime.now(timezone.utc).isoformat(),"noise":base64.b64encode(os.urandom(128)).decode()}
        self.valid_token_ids_per_user[user_id] = token["session_id"]
        self.valid_token_ids.append(token["session_id"])
        return token
    def _validate_token(self, token,user_id):
        token_time = token['timestamp']
        timestamp = datetime.fromisoformat(token_time)
        now = datetime.now(timezone.utc)
        if token["user_id"] != user_id:
            return False
        elif token["session_id"] not in self.valid_token_ids:
            return False
        elif self.valid_token_ids_per_user[user_id] != token["session_id"]:
            return False
        elif now - timestamp > timedelta(minutes=20):
            return False
        return True
    def _handle_share_aes(self,data:dict):
        try:
            aes_key_enc = data.get("aes_key",None)
            user_id_enc = data.get("user_id",None)
            aes_key = sec.rsa_decrypt_key(aes_key_enc,self.rsa_private_key)
            user_id = sec.decrypt_user_id(user_id_enc,self.rsa_private_key)
            token = self._create_token(user_id)
            try:
                token_enc = self.master_aes_class.encrypt(json.dumps(token).encode())
                certificate = self.cert
                key_bytes = base64.urlsafe_b64decode(aes_key)
                aes_key = key_bytes
                # ##print(len(key_bytes))  # Should be 32 for AES-256
                temp_class = httpe_fernet.HttpeFernet(aes_key)
                certificate_enc = temp_class.encrypt(json.dumps(certificate).encode())
                ret_data = {"token":token_enc,"certificate":certificate_enc}
            except Exception as e:
                self._log_internal_error(e)

                ##print(f"Failed to enc {e}")
            self.user_keys[user_id] = aes_key
            res = Response(json.dumps(ret_data))
            return res
        except Exception as e:
            self._log_internal_error(e)

            ##print(f"_handle_share_aes error {e}")
    def _handle_enc_request(self,data:str):
        user_id_enc = None
        aes_key_to_use = None
        found_id = False
        enc_data = None
        ##print("HTTPE_SERVER__handle_enc_request == ",data)
        for line in data:
            if line.startswith("TOKEN:"):
                enc_token = line.split(":", 1)[1].strip()
                try:
                    plain_token = self.master_aes_class.decrypt(enc_token)
                    json_token = json.loads(plain_token)
                except Exception as e:
                    self._log_internal_error(e)

                    return None,None
                # ##print(json_token)
                user_id = json_token["user_id"]
                if(self._validate_token(json_token,user_id) == False):
                    return None,None
                aes_key_to_use = self.user_keys[user_id]
                found_id = True
            elif(found_id == True):
                enc_data = line
                break
        # decrypted_data = sec.fernet_decrypt(enc_data,aes_key_to_use)
        temp_class = httpe_fernet.HttpeFernet(aes_key_to_use)
        decrypted_data = temp_class.decrypt(enc_data).decode()
        ##print("HTTPE_DECRYPTED_DATA_decrypted_data == ",decrypted_data)
        return decrypted_data,user_id
    def _handle_packet_contents(self,lines):
        headers = {}
        version = None
        is_initial_packet = None
        initial_packet_type = None
        method = None
        location = None
        reading_headers = False
        body = ""
        for line in lines:
            # ##print(line)
            line = line.strip()
            if line.startswith("VERSION:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("TYPE:"):
                is_initial_packet = True
                initial_packet_type = line.split(":", 1)[1].strip().upper()
                if(initial_packet_type == "REQ_ENC"):
                    break
            elif line.startswith("METHOD:"):
                method = line.split(":", 1)[1].strip().upper()
            elif line.startswith("LOCATION:"):
                location = line.split(":", 1)[1].strip()
            elif line.startswith("HEADERS:"):
                reading_headers = True
            elif line == "END":
                reading_headers = False
            elif reading_headers and ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
            elif not reading_headers:
                body += line + "\n"
        return headers,version,is_initial_packet,initial_packet_type,method,location,body
    def _log_request(self, path, valid, client_ip, header, data):
        logging.info(f"Request to {path} by {client_ip}. Header: {header} Body: {data}")

    def _log_failed_verification(self, client_id, client_ip,notes):
        logging.warning(f"Failed to verify user {client_id} from {client_ip}. {notes}")

    def _log_internal_error(self, error: Exception):
        logging.error(f"Internal server error: {error}", exc_info=True)
    def compute_hashed_identity(self,name:str, salt: str) -> str:
        # return name
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    def _send_connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((self.edoi_ip, self.edoi_port))
            ##print(f"[+] Connected to EDOI node at {self.edoi_ip}:{self.edoi_port}")

            # Send a message to the EDOI node
            message = json.dumps({"type": "connect","tup":(self.host,self.port)}).encode('utf-8')
            client_socket.sendall(message)
    def _handle_client(self, conn, addr):
        print(f"Got request at {time.time()}")
        # start_time_timer = time.start()
        try:
            try:
                data = b""
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    # ##print(chunk)
                    if b"END\n" in data or b"END\r\n" in data or b"END" in data:
                        break
                
            except Exception as e:
                self._log_internal_error(e)
                err_res =  Response.error(message="Internal Server Error",status_code=500)
                # conn.sendall(err_res.serialize().encode())
                self.send_packet(conn,addr=addr,data=err_res.serialize().encode(),route=None)
                return
            # ##print(type(data))
            route=None
            if(self.is_edoi_node == True):
                edoi_decoded = data.decode('utf-8')
                try:
                    edoi_json_data = json.loads(edoi_decoded)
                    # ##print(edoi_json_data)
                except Exception as e:
                    err_res =  Response.error(message=f"Internal Server Error {e}",status_code=500)
                    # conn.sendall(err_res.serialize().encode())
                    ##print(err_res.serialize().encode())
                    self.send_packet(conn,addr=addr,data=err_res.serialize().encode(),route=None)
                    return
                # data = data.decode()
                edoi_packet_type = edoi_json_data.get("type",None)
                route = None
                if(edoi_packet_type == "find"):
                    ##print("PAth search")
                    route = edoi_json_data.get("route", None)
                    target_hash = edoi_json_data.get("hash", None)
                    if route and target_hash:
                        salt = edoi_json_data.get("salt", None)
                        name_hash = self.compute_hashed_identity(self.name, salt)
                        if name_hash == target_hash:
                            # print("Got EDOI-NET connection")
                            route_member = {"hash":name_hash,"salt":salt}
                            route.append(route_member)
                            ret_data = {"type":"path","route":route,"count":len(route)-2,"hash":target_hash,"salt":salt,"node_ip":(self.host,self.port)}
                            ret_data["message_id"] = str(uuid.uuid4())
                            try:
                                json_str = json.dumps(ret_data)
                                encoded = json_str.encode('utf-8')

                                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                                    client_socket.connect((self.edoi_ip, self.edoi_port))
                                    client_socket.sendall(encoded)
                                ##print("Sent path message")
                                return
                            except Exception as e:

                                print(f"[!] Error sending data: {e}")
                elif(edoi_packet_type == "forward"):
                    
                    count = edoi_json_data.get("count",None)
                    route = edoi_json_data.get("route",None)
                    end_point = route[count]
                    salt = route[count]["salt"]

                    end_hash = end_point.get("hash",None)
                    my_hash = self.compute_hashed_identity(self.name,salt)
                    if(my_hash == end_hash):
                        print(f"Server:Forward:{time.time()}")
                        file = open("../run_output.log","a")
                        file.write(f"Server:Forward:{time.time()}\n")
                        file.close()
                        # httpe_logging.sync_log(f"Server:Forward:{time.time()}")

                        pass
                    else:
                        return


                try:
                    data = edoi_json_data.get("payload",None)
                except Exception as e:
                    err_res =  Response.error(message=f"Internal Server Error {e}",status_code=500)
                    # conn.sendall(err_res.serialize().encode())
                    ##print(err_res.serialize().encode())
                    self.send_packet(conn,addr=addr,data=err_res.serialize().encode(),route=route)
                    return




            # ##print(data)
            try:
                text = data.decode()
            except AttributeError as e:
                text = data
            lines = text.splitlines()

            version = None
            method = None
            location = None
            is_initial_packet = False
            initial_packet_type = None
            headers = {}
            body = ""
            is_encrypted_packet = False
            user_id_from_token = None
            # ##print(text)
            reading_headers = False
            headers,version,is_initial_packet,initial_packet_type,method,location,body  = self._handle_packet_contents(lines)
            ##print(">>",version)
            ##print(">>",initial_packet_type)
            if(version != f"HTTPE/{self.version}"):
                err_res =  Response.error(message="Invalid Version",status_code=400)
                # conn.sendall(err_res.serialize().encode())
                ## DIsbaled for debug
                self.send_packet(conn,addr,data=err_res.serialize().encode(),route=route)
            if(is_initial_packet == True):
                if(initial_packet_type == "GET_RSA"):
                    send_rsa_pub = {"rsa":self.rsa_public_key_shared}
                    rsa_rez = Response(json.dumps(send_rsa_pub))
                    # conn.sendall(rsa_rez.serialize().encode())
                    self.send_packet(conn,addr,data=rsa_rez.serialize().encode(),route=route)
                    return
                elif(initial_packet_type == "SHARE_AES"):
                    # ##print(headers)
                    res_data = self._handle_share_aes(headers)
                    # conn.sendall(res_data.serialize().encode())
                    self.send_packet(conn,addr,data=res_data.serialize().encode(),route=route)
                    return
                elif(initial_packet_type == "REQ_ENC"):
                    start_enc_time_timer = time.time()
                    new_lines,user_id_from_token =  self._handle_enc_request(lines)
                    if(new_lines == None or user_id_from_token == None):
                        #! Remove {e} in prod
                        # self._log_internal_error(e)

                        err_res =  Response.error(message=f"Error With Client handling code: user_id_from_token: {user_id_from_token}, new_lines: {new_lines}",status_code=500)
                        # conn.sendall(err_res.serialize().encode())
                        self.send_packet(conn,addr,data=err_res.serialize().encode(),route=route)
                        return
                    new_lines = new_lines.splitlines()
                    is_encrypted_packet = True
                    headers,version,is_initial_packet,initial_packet_type,method,location,body  =self._handle_packet_contents(new_lines)
                    end_enc_time_timer = time.time()


            # ##print("headers>>",headers)
            packet_validation_time_start = time.time()
            packet_id = headers.get("packet_id",None)
            
            header_user_id = headers.get("client_id",None)
            if(str(header_user_id) != str(user_id_from_token)):
                self._log_failed_verification(header_user_id,addr,"clientID x TokenID mismatch")
                err_res =  Response.error(message="Invalid Token",status_code=608)
                # conn.sendall(err_res.serialize().encode())
                self.send_packet(conn,addr,data=err_res.serialize().encode(),route=route)
                return
            if(packet_id == None):
                self._log_failed_verification(header_user_id,addr,"invalid packet")
                err_res =  Response.error(message="packet_id missing",status_code =400)
                self.send_packet(conn,addr,data=err_res.serialize().encode(),route=route)
                return
            # ##print(f"HTTPE {method} {location} from {addr} with headers {headers}")
            timestamp = headers.get("timestamp", None)
            if(timestamp == None):
                err_res =  Response.error(message="Invalid Timestamp",status_code=608)
                self._log_failed_verification(header_user_id,addr,"invalid packet")
                # conn.sendall(err_res.serialize().encode())
                self.send_packet(conn,addr,data=err_res.serialize().encode(),route=route)
                return
            timestamp = datetime.fromisoformat(timestamp)
            now = datetime.now(timezone.utc)
            if now - timestamp > timedelta(minutes=2):
                self._log_failed_verification(header_user_id,addr,"Possible packet reuse")
                err_res =  Response.error(message="Old Timestamp",status_code=607)
                # conn.sendall(err_res.serialize().encode())
                self.send_packet(conn,addr,data=err_res.serialize().encode(),route=route)
                return
            handler = self.routes.get((location, method))
            ##print(">>",location, method)
            try:
                self._log_request(path=location,client_ip=addr,header=headers,data=body,valid=True)
            except Exception as e:
                self._log_internal_error(e)

                ##print(f"Failed to lof file {e}")
            if handler:
                sig = inspect.signature(handler)
                if(len(sig.parameters) == 0):


                    result = self._parse_handler(handler,sig,None,self.user_keys[header_user_id])
                    if not isinstance(result, Response):
                        result = Response(str(result))  # fallback
                    response = result.serialize()
                    if not isinstance(result, Response):
                        result = Response(str(result))  # fallback
                    response = result.serialize()
                else:
                    handler_start_time = time.time()
                    result = self._parse_handler(handler,sig,json.loads(body),self.user_keys[header_user_id])
                    if not isinstance(result, Response):
                        result = Response(str(result))  # fallback
                    response = result.serialize()
            else:
                # ##print("Cant find route for type:",initial_packet_type)
                result = "Route Not Found"
                if not isinstance(result, Response):
                        result = Response(str(result))  # fallback
                response = result.serialize()

            # conn.sendall(response.encode())
            self.send_packet(conn,addr,data=response.encode(),route=route)
        except Exception as e:
            self._log_internal_error(e)

            #! Remove {e} in prod
            err_res =  Response.error(message=f"Error With Client handling code :{e}",status_code=500)
            # conn.sendall(err_res.serialize().encode())
            ##print(err_res.serialize().encode())
            self.send_packet(conn,addr,data=err_res.serialize().encode(),route=None)
            return
        finally:
            conn.close()
    def _parse_handler(self, handler,sig,body,aes_key):
        if(body != None):
            kwargs = {}
            for val in body.keys():
                ##print(val,sig.parameters)
                if val not in sig.parameters:
                    
                    err_res =  Response.error(message="Invalid Parameter",status_code=400)
            #         # 
                    return err_res
            for name, param in sig.parameters.items():
                if(name in body):
                    kwargs[name] = body[name]
                else:
                    err_res =  Response.error(message="Invalid Parameter",status_code=400)
                    # 
                    return err_res
            
            res_data = handler(**kwargs)
        else:
            res_data = handler()
        temp_class = httpe_fernet.HttpeFernet(aes_key)
        if(isinstance(res_data, Response)):
            plain_b = res_data.body
            error_code = res_data.status_code
            enc_data = temp_class.encrypt(json.dumps(plain_b).encode("utf-8"))
            enc_res =Response(enc_data,status_code=error_code)
            return enc_res
        enc_data = temp_class.encrypt(json.dumps(res_data).encode("utf-8"))

        return enc_data
    def redirect(self,redirect_url,status=302,**kwargs):
        paths = [key[0] for key in self.routes.keys()]
        if(redirect_url not in paths):
            err_res =  Response.error(message="Redirect Url Invalid",status_code=500)
            return err_res
        
        else:
            body = {"redirect_url_endpoint":redirect_url}
            res = Response(json.dumps(body),status_code=status)
            return res
    
    def send_packet(self,conn,addr,data,route=None):
        try:
            if(self.is_edoi_node == False):
                print("Sending using conn")
                conn.sendall(data)
            else:
                if(route == None or len(route) < 2):
                    return
                count = len(route) - 2
                packet = {
                    "type": "return",
                    "route": route,
                    "count": count,
                    "payload": data.decode("utf-8"),
                    "ip_combo":(self.host,self.port)
                }
                print(f"Server:Return:{time.time()}")
                file = open("../run_output.log","a")
                file.write(f"Server:Return:{time.time()}\n")
                file.close()
                # httpe_logging.sync_log(f"Server:Return:{time.time()}")

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    client_socket.connect((self.edoi_ip, self.edoi_port))
                    message = json.dumps(packet).encode('utf-8')
                    client_socket.sendall(message)
                return
        except Exception as e:
            print(f"{self.name} error in send packet: ")
    # def edoi_net_rec()