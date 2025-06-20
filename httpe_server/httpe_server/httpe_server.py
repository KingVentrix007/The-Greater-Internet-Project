from cryptography.hazmat.primitives import hashes
import time
import os
import inspect
import json
from httpe_core.httpe_class import Response
import httpe_core.httpe_error as httpe_error
from datetime import datetime, timezone, timedelta
import httpe_core.httpe_secure as sec
import uuid
import base64
import httpe_core.httpe_fernet as httpe_fernet
import logging
import re
import asyncio
import httpe_core.httpe_cert as httpe_cert
import httpe_core.httpe_keys as httpe_keys
from httpe_core.httpe_types import APPLICATION_JSON
from rich.console import Console
from rich.prompt import Prompt



class Httpe:
    def __init__(self,server_host="127.0.0.1",port=8080,running_version="1.0",crte_file_path="cert.crte",key_dir_path=".",name="edoi node",use_edoi_node=False,edoi_ip=None,edoi_port=None,debug_mode=False):
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
        self.console = Console()
        self.key_dir_path = key_dir_path
        self.console.print("[bold blue][INFO] HTTPE Server Initializing...[/]")
        if(os.path.exists(self.cert_path) == False or os.path.exists(f"{self.key_dir_path}/private_key.edoi") == False or os.path.exists(f"{self.key_dir_path}/public_key.edoi") == False):
            self.console.print("[bold red] [ERROR] Necessary files cannot be found.",end="")
            action = Prompt.ask("[bold red] Do you want to create them(Y/N)")
            action = action.upper()
            if(action == "" or action == "N"):
                raise FileNotFoundError("The Necessary file could not be found")
            elif(action == "Y"):
                self.console.print("[grey50] Generating PEM files...")
                httpe_cert.create_pem_files(".",".")
                self.console.print("[grey50] Generating RSA keypair...")
                pub_key, _ = httpe_keys.save_keys_rsa_keys()
                self.console.print("[grey50] Creating certificate...")
                httpe_cert.create_corticate(
                    hostname=server_host,
                    save=True,
                    cert_pub_key=pub_key,
                    valid_time_days=100
                )

            

        self.routes = {}
        self.host = server_host
        self.port = port
        self.valid_token_ids = []
        self.valid_token_ids_per_user = {}
        self.user_keys = {}
        self.rsa_private_key = None
        self.rsa_public_key_shared = None
        self.master_aes_class = httpe_fernet.HttpeFernet()
        self.cert = None
        self._load_keys()
        self.load_cert()
        self.version = running_version
        logging.basicConfig(filename='logfile.log', level=logging.INFO, format='[I]%(asctime)s: %(message)s', datefmt='%Y-%m-%dT%H:%M:%SZ')
        self.is_edoi_node = use_edoi_node
        self.name = name
        self.edoi_ip = edoi_ip
        self.edoi_port = edoi_port
        self._debug_mode = debug_mode
    def _shutdown(self):
        self.console.print("[blue][INFO] Purging users")
        self.user_keys.clear()
        if(len(self.user_keys) > 0):
            self.console.print("[bold red][!] Failed to purge users")
        self.console.print("[bold green][Success]Purged users")
        self.console.print("[blue][INFO] Purging token ids")
        self.valid_token_ids.clear()
        self.valid_token_ids_per_user.clear()
        if(len(self.valid_token_ids) > 0 or len(self.valid_token_ids_per_user) > 0):
            self.console.print("[bold red][!] Failed to purge token IDs")
        self.console.print("[bold green][[Success]]Purged token ids")
    def _load_keys(self):
        try:
            with open("private_key.edoi","r") as f:
                key_data = json.load(f)
                expire_data = key_data['valid_to']
                timestamp = datetime.fromisoformat(expire_data)
                now = datetime.now(timezone.utc)
                if now - timestamp > timedelta(minutes=20):
                    raise httpe_error.PrivateKeyExpiredError("Private key expired")
                key = key_data["key"]
                self.rsa_private_key = key
            with open("public_key.edoi","r") as f:
                key_data = json.load(f)
                expire_data = key_data['valid_to']
                timestamp = datetime.fromisoformat(expire_data)
                now = datetime.now(timezone.utc)
                if now - timestamp > timedelta(minutes=20):
                    raise httpe_error.PublicKeyExpiredError("Public key expired")
                key = key_data["key"]
                self.rsa_public_key_shared = key
        except Exception as e:
            self._log_internal_error(e)
            self.console.print(f"[bold red][ERROR] Failed to handle key files: {e}")
            self.rsa_private_key = None
            self.rsa_public_key_shared = None

        
    def load_cert(self):
        try:
            with open("cert.crte","r") as f:
                self.cert = json.load(f)
        except FileNotFoundError:
            self.console.print("[bold red][ERROR] Cannot find cert.crte. Please ensure it is placed in the same dir as the main server file")
            self.cert = None
        except Exception as e:
            self._log_internal_error(e)
            self.console.print(f"[bold red] General error loading cert.crte {e}")
            self.cert = None
    def path(self, route, method="GET"):
        def decorator(func):
            self.routes[(route, method)] = func
            return func
        return decorator
    def paths(self):
        for (route, method), func in self.routes.items():
            print(f"{method} {route} -> {func.__name__}")
    def start(self):
        try:
            asyncio.run(self.serve())
        except KeyboardInterrupt:
            
            self.console.print("[blue][INFO]Shutting down server...")
            self._shutdown()
            self.console.print("[blue][INFO]Server shutdown")
    async def serve(self):
        if(self.is_edoi_node == True):
            await self._send_connect()
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        async with self._server:
            self.console.print(f"[bold blue][INFO] Server running on {self.host}:{self.port}")
            await self._server.serve_forever()
        
                                # ##print("[*] Connection closed.\n")
    async def _create_token(self, user_id):
        
        token = {"user_id":user_id,"session_id":str(uuid.uuid4()),"timestamp":datetime.now(timezone.utc).isoformat(),"noise":base64.b64encode(os.urandom(128)).decode()}
        self.valid_token_ids_per_user[user_id] = token["session_id"]
        self.valid_token_ids.append(token["session_id"])
        return token
    async def _validate_token(self, token,user_id):
        token_time = token['timestamp']
        timestamp = datetime.fromisoformat(token_time)
        now = datetime.now(timezone.utc)
        if token["user_id"] != user_id or token["session_id"] not in self.valid_token_ids or self.valid_token_ids_per_user[user_id] != token["session_id"] or now - timestamp > timedelta(minutes=20):
            return False
        return True
    async def _handle_share_aes(self,data:dict):
        # print("Handling share aes")
        try:
            aes_key_enc = data.get("aes_key",None)
            user_id_enc = data.get("user_id",None)
            aes_key = sec.rsa_decrypt_key(aes_key_enc,self.rsa_private_key)
            user_id = sec.decrypt_user_id(user_id_enc,self.rsa_private_key)
            token = await self._create_token(user_id)
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
                await self._log_internal_error(e)

                ##print(f"Failed to enc {e}")
            self.user_keys[user_id] = aes_key
            res = Response(json.dumps(ret_data))
            return res
        except Exception as e:
            await self._log_internal_error(e)

            ##print(f"_handle_share_aes error {e}")
    async def _handle_enc_request(self,data:str):
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
                    await self._log_internal_error(e)

                    return None,None
                # ##print(json_token)
                user_id = json_token["user_id"]
                if(await self._validate_token(json_token,user_id) == False):
                    return None,None
                aes_key_to_use = self.user_keys[user_id]
                found_id = True
            elif(found_id == True):
                enc_data = line
                break
        temp_class = httpe_fernet.HttpeFernet(aes_key_to_use)
        decrypted_data = temp_class.decrypt(enc_data).decode()
        ##print("HTTPE_DECRYPTED_DATA_decrypted_data == ",decrypted_data)
        return decrypted_data,user_id
    async def _handle_packet_contents(self,lines):
        headers = {}
        version = None
        is_initial_packet = None
        initial_packet_type = None
        method = None
        location = None
        reading_headers = False
        body = ""
        for line in lines:
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
    async def _log_request(self, path, valid, client_ip, header, data):
        is_valid = "valid" if valid == True else "invalid"
        logging.info(f"Request to {is_valid}:{path} by {client_ip}. Header: {header} Body: {data}")

    async def _log_failed_verification(self, client_id, client_ip,notes):
        logging.warning(f"Failed to verify user {client_id} from {client_ip}. {notes}")

    async def _log_internal_error(self, error: Exception):
        logging.error(f"Internal server error: {error}", exc_info=True)
    async def compute_hashed_identity(self,name:str, salt: str) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    async def _send_connect(self):
        try:
            _, writer = await asyncio.open_connection(self.edoi_ip, self.edoi_port)
            # print(f"[+] Connected to EDOI node at {self.edoi_ip}:{self.edoi_port}")

            # Prepare the message
            message = json.dumps({
                "type": "connect",
                "tup": (self.host, self.port)
            }).encode('utf-8')

            # Send the message
            writer.write(message)
            await writer.drain()

            # Optional: Close the connection
            writer.close()
            await writer.wait_closed()

        except Exception as e:
            print(f"Failed to connect to EDOI node: {e}")
    async def validate_packet(self,headers,route,writer,addr,user_id_from_token):
            packet_validation_time_start = time.time()
            packet_id = headers.get("packet_id",None)
            
            header_user_id = headers.get("client_id",None)
            if(str(header_user_id) != str(user_id_from_token)):
                await self._log_failed_verification(header_user_id,addr,"clientID x TokenID mismatch")
                err_res =  Response.error(message="Invalid Token",status_code=608)
                # conn.sendall(err_res.serialize().encode())
                print(err_res.serialize().encode())
                await self.send_packet(writer,addr,data=err_res.serialize().encode(),route=route)
                return False
            if(packet_id == None):
                await self._log_failed_verification(header_user_id,addr,"invalid packet")
                err_res =  Response.error(message="packet_id missing",status_code =400)
                print(err_res.serialize().encode())
                await self.send_packet(writer,addr,data=err_res.serialize().encode(),route=route)
                return False
            # ##print(f"HTTPE {method} {location} from {addr} with headers {headers}")
            timestamp = headers.get("timestamp", None)
            if(timestamp == None):
                err_res =  Response.error(message="Invalid Timestamp",status_code=608)
                await self._log_failed_verification(header_user_id,addr,"invalid packet")
                # conn.sendall(err_res.serialize().encode())
                print(err_res.serialize().encode())
                await self.send_packet(writer,addr,data=err_res.serialize().encode(),route=route)
                return False
            timestamp = datetime.fromisoformat(timestamp)
            now = datetime.now(timezone.utc)
            if now - timestamp > timedelta(minutes=2):
                self._log_failed_verification(header_user_id,addr,"Possible packet reuse")
                err_res =  Response.error(message="Old Timestamp",status_code=607)
                # conn.sendall(err_res.serialize().encode())
                print(err_res.serialize().encode())
                await self.send_packet(writer,addr,data=err_res.serialize().encode(),route=route)
                return False
            validate_packet_time_end = time.time()
            if(self._debug_mode == True):
                print("[DEBUG]:Server:Time to validate packet:",validate_packet_time_end-packet_validation_time_start)
            return True
    async def _handle_edoi_find(self,edoi_json_data):
        ##print("PAth search")
                    route = edoi_json_data.get("route", None)
                    target_hash = edoi_json_data.get("hash", None)
                    if route and target_hash:
                        salt = edoi_json_data.get("salt", None)
                        name_hash = await self.compute_hashed_identity(self.name, salt)
                        if name_hash == target_hash:
                            # print("Got EDOI-NET connection")
                            route_member = {"hash":name_hash,"salt":salt}
                            route.append(route_member)
                            ret_data = {"type":"path","route":route,"count":len(route)-2,"hash":target_hash,"salt":salt,"node_ip":(self.host,self.port)}
                            ret_data["message_id"] = str(uuid.uuid4())
                            try:
                                json_str = json.dumps(ret_data)
                                encoded = json_str.encode('utf-8')

                                try:
                                    _, writer = await asyncio.open_connection(self.edoi_ip, self.edoi_port)

                                    writer.write(encoded)
                                    await writer.drain()

                                    writer.close()
                                    await writer.wait_closed()

                                except Exception as e:
                                    print(f"Error sending to EDOI node: {e}")
                                return None
                            except Exception as e:

                                print(f"[!] Error sending data: {e}")
    async def _handle_edoi_forward(self,edoi_json_data):
        # print("Forward request received. Processing...")
        count = edoi_json_data.get("count",None)
        route = edoi_json_data.get("route",None)
        end_point = route[count]
        salt = route[count]["salt"]

        end_hash = end_point.get("hash",None)
        my_hash = await self.compute_hashed_identity(self.name,salt)
        if(my_hash == end_hash):
            return True
            # httpe_logging.sync_log(f"Server:Forward:{time.time()}")

        else:
            # print("No match")
            return False
    async def handle_edoi_packet(self,data,addr,conn):

                edoi_decoded = data.decode('utf-8')
                try:
                    edoi_json_data = json.loads(edoi_decoded)
                    # ##print(edoi_json_data)
                except Exception as e:
                    err_res =  Response.error(message=f"Internal Server Error {e}",status_code=500)
                    print(f"[ERROR] {err_res.serialize()}")
                    self.send_packet(conn,addr=addr,data=err_res.serialize().encode(),route=None)
                    return None, edoi_json_data.get("route",None)
                edoi_packet_type = edoi_json_data.get("type",None)
                route = None
                if(edoi_packet_type == "find"):
                    await self._handle_edoi_find(edoi_json_data=edoi_json_data)
                    return False,False
                elif(edoi_packet_type == "forward"):
                    is_target = await self._handle_edoi_forward(edoi_json_data)
                    if(is_target == True):
                        data = edoi_json_data.get("payload",None)
                        return data,edoi_json_data.get("route",None)
                    return None,edoi_json_data.get("route",None)
                else:
                    try:
                        data = edoi_json_data.get("payload",None)
                        return data,edoi_json_data.get("route",None)
                    except Exception as e:
                        err_res =  Response.error(message=f"Internal Server Error {e}",status_code=500)
                        print(f"[ERROR] {err_res.serialize().encode()}")
                        self.send_packet(conn,addr=addr,data=err_res.serialize().encode(),route=route)
                        return None,edoi_json_data.get("route",None)
    async def find_dynamic_route(self,routes, path, method):
        for (route_pattern, route_method), handler in routes.items():
            if route_method != method:
                continue

            # Convert pattern to regex, e.g., "/user/{id}" -> "^/user/(?P<id>[^/]+)$"
            regex = re.sub(r'\{(\w+)\}', r'(?P<\1>[^/]+)', route_pattern)
            regex = f"^{regex}$"
            match = re.match(regex, path)
            if match:
                return handler, match.groupdict()  # return handler and extracted params

        return None, {}
    async def _receive_connection_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            addr = writer.get_extra_info('peername')
            self.console.print(f"[green][+]Received connection from {addr}")
            try:
                data = b""
                res_time_start = time.time()
                while True:
                    chunk = await reader.read(4096)  # Read in chunks
                    data += chunk
                    # print(f"Chunk:{chunk}")
                    if not chunk:
                        break
                    
                    
                    if "END\n" in chunk.decode():
                        break
                    # print(f"Data :{data}")
                res_time_end = time.time()
                if(self._debug_mode == True):
                    print(f"[DEBUG]:Server:Time to receive packet:{res_time_end-res_time_start}")
            except Exception as e:
                await self._log_internal_error(e)
                err_res =  Response.error(message="Internal Server Error",status_code=500)
                # conn.sendall(err_res.serialize().encode())
                await self.send_packet(writer,addr=addr,data=err_res.serialize().encode(),route=None)
                return None,None
            return data,addr
    async def _handle_packets(self,lines,data,writer,addr,route):
        headers,version,_,initial_packet_type,method,location,body  = await self._handle_packet_contents(lines)
        if(version != f"HTTPE/{self.version}"):
            err_res =  Response.error(message="Invalid Version",status_code=400)
            await self.send_packet(writer,addr,data=err_res.serialize().encode(),route=route)
        if(initial_packet_type == "GET_RSA"):
            send_rsa_pub = {"rsa":self.rsa_public_key_shared}
            rsa_rez = Response(json.dumps(send_rsa_pub))
            await self.send_packet(writer,addr,data=rsa_rez.serialize().encode(),route=route)
            return None,None,None,None,None
        elif(initial_packet_type == "SHARE_AES"):
            res_data = await self._handle_share_aes(headers)
            await self.send_packet(writer,addr,data=res_data.serialize().encode(),route=route)
            # print("Send aes response")
            return None,None,None,None,None
        elif(initial_packet_type == "REQ_ENC"):
            # print("Enc req")
            new_lines,user_id_from_token =  await self._handle_enc_request(lines)
            if(new_lines == None or user_id_from_token == None):
                #! Remove {e} in prod
                # self._log_internal_error(e)

                err_res =  Response.error(message=f"Error With Client handling code: user_id_from_token: {user_id_from_token}, new_lines: {new_lines}",status_code=500)
                # conn.sendall(err_res.serialize().encode())
                await self.send_packet(writer,addr,data=err_res.serialize().encode(),route=route)
                return None,None,None,None,None
            new_lines = new_lines.splitlines()
            headers,version,_,initial_packet_type,method,location,body  =await self._handle_packet_contents(new_lines)
        elif(initial_packet_type == "ENC_END"):
            new_lines,user_id_from_token =  await self._handle_enc_request(lines)
            try:
                del self.user_keys[user_id_from_token]
                token_to_remove = self.valid_token_ids_per_user[user_id_from_token]
                del self.valid_token_ids_per_user[user_id_from_token]
                self.valid_token_ids.remove(token_to_remove)
            except Exception as e:
                await self._log_internal_error(e)
                print(f"Failed to delete user key {e}")
            return None,None,None,None,None
            

        else:
            print(f"WHAT IS THIS: {data}")
        header_user_id = headers.get("client_id",None)
        valid_packet = await self.validate_packet(headers=headers,route=route,writer=writer,addr=addr,user_id_from_token=header_user_id)
        if(valid_packet == False):
            return None,None,None,None,None
        return headers,method,location,body,header_user_id
    async def _handle_no_parm_endpoint(self,handler,sig,header_user_id,content_type,accepts):
        result = await self._parse_handler(handler,sig,None,self.user_keys[header_user_id],content_type,accepts)
        if not isinstance(result, Response):
            result = Response(str(result))  # fallback
        response = result.serialize()
        return response
    async def _handle_standard_endpoint(self,handler,sig,body,header_user_id,content_type,accepts,url_params):
        parsed_input = json.loads(body or "{}")
        if(parsed_input == None):
            parsed_input = body
        else:
            parsed_input.update(url_params)  # Merge path params with JSON body

        result = await self._parse_handler(handler,sig,parsed_input,self.user_keys[header_user_id],content_type,accepts)
        if not isinstance(result, Response):
            result = Response(str(result))  # fallback
        response = result.serialize()
        return response
    async def _process_edoi_data(self,user_data,addr,writer):
        try:
            edoi_data,route  = await self.handle_edoi_packet(data=user_data,addr=addr,conn=writer)
        except Exception as e:
            print(f"[ERROR]. EDOI handle: {e}")
        if(edoi_data != None):
            if(edoi_data == False and route == False):
                self.console.print("[bold red][ERROR] Failed to extract edoi data and route from edoi packet")
                return None,None
            data=edoi_data
        else:
            return data,route
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            data,addr = await self._receive_connection_data(reader,writer)
            if(addr == None or data == None):
                self.console.print(f"[bold red][ERROR] Failed to receive data from client({addr if addr != None else "N/A"})")
                return
            # ##print(type(data))
            route=None
            if(self.is_edoi_node == True):
                data,route = await self._process_edoi_data(user_data=data,addr=addr,writer=writer)
            # print(data)
            # try:
            text = data.decode()
            # except AttributeError as e:
            #     text = data
            lines = text.splitlines()
            method = None
            location = None
            headers = {}
            body = ""
            headers,method,location,body,header_user_id = await self._handle_packets(lines,data,writer,addr,route)
            if(any(x is None for x in (headers,method,location,body))):
                return
            handler, url_params = await self.find_dynamic_route(self.routes, location, method)
            
            ##print(">>",location, method)
            try:
                await self._log_request(path=location,client_ip=addr,header=headers,data=body,valid=True)
            except Exception as e:
                await self._log_internal_error(e)

                ##print(f"Failed to lof file {e}")
            content_type = headers.get("Content-Type", APPLICATION_JSON)
            accepts = headers.get("Accepts", APPLICATION_JSON)
            if handler:
                sig = inspect.signature(handler)
                if(len(sig.parameters) == 0):
                    response = await self._handle_no_parm_endpoint(handler,sig,header_user_id,content_type,accepts)
                else:
                    response = await self._handle_standard_endpoint(handler=handler,sig=sig,body=body,header_user_id=header_user_id,content_type=content_type,accepts=accepts,url_params=url_params)
            else:
                # ##print("Cant find route for type:",initial_packet_type)
                result = "Route Not Found"
                if not isinstance(result, Response):
                        result = Response(str(result),status_code=404,status="404 NOT FOUND")  # fallback
                response = result.serialize()

            # conn.sendall(response.encode())

            await self.send_packet(writer,addr,data=response.encode(),route=route)
        except Exception as e:
            await self._log_internal_error(e)
            err_res =  Response.error(message=f"Error With Client handling code :{e}",status_code=500)
            self.console.log(f"[bold red][ERROR] {err_res.serialize().encode()}\n||")
            await self.send_packet(writer,addr,data=err_res.serialize().encode(),route=None)
            return
        finally:
            writer.close()
            await writer.wait_closed()
    async def _parse_handler_json(self, handler,sig,body):
        if(isinstance(body,str) == True):
            try:
                body = json.loads(body)
            except Exception as e:
                print(f"[ERROR] Failed to load body as json: {e}:{body}")
                err_res =  Response.error(message="Invalid JSON",status_code=400)
                return err_res

        kwargs = {}
        for val in body.keys():
            if val not in sig.parameters:
                
                err_res =  Response.error(message="Invalid Parameter",status_code=400)
        #         # 
                return err_res
        for name, _ in sig.parameters.items():
            if(name in body):
                kwargs[name] = body[name]
            else:
                err_res =  Response.error(message="Invalid Parameter",status_code=400)
                # 
                return err_res
        
        res_data = await handler(**kwargs)
        return res_data
    async def _parse_handler_with_contents(self, handler,sig,body,content_type):
        if content_type == APPLICATION_JSON:
                res_data = await self._parse_handler_json(handler, sig, body)
        elif content_type in ("text/plain", "text/html", "application/octet-stream"):
            res_data = await handler(body)
        else:
            res_data =  Response.error(message=f"Unsupported Media Type: {content_type}",status_code=415)
        return res_data
    async def _parse_handler(self, handler,sig,body,aes_key,content_type=APPLICATION_JSON,accepts=APPLICATION_JSON):
        if body is not None:
            res_data = await self._parse_handler_with_contents(handler,sig,body,content_type)
        else:
            res_data = await handler()

        temp_class = httpe_fernet.HttpeFernet(aes_key)
        if(isinstance(res_data,(dict,tuple))):
            try:
                # print("Hello world")
                new_res = Response(body=res_data[0],status_code=int(res_data[1]))
                res_data = new_res
            except Exception as e:
                self.console.log(f"[bold red][ERROR]: Error in parse handler {e}")
        if isinstance(res_data, Response):
            plain_b = res_data.body
            error_code = res_data.status_code

            if accepts == APPLICATION_JSON:
                # Make sure it's JSON-serializable
                try:
                    json_payload = json.dumps(plain_b)
                except (TypeError, ValueError):
                    # Not JSON-serializable, return error instead
                    err_res = Response.error(
                        message=f"Endpoint response type doesn't match requested type {accepts}",
                        status_code=415
                    )
                    json_payload = json.dumps({"error": err_res.message})
                    error_code = err_res.status_code
            elif accepts == "text/html":
                json_payload = plain_b#json.dumps({"data": plain_b})
            else:
                json_payload = plain_b
                

            enc_data = temp_class.encrypt(json_payload.encode("utf-8"))
            return Response(enc_data, status_code=error_code)
        enc_data = temp_class.encrypt(json.dumps(res_data).encode("utf-8"))

        return enc_data
    async def redirect(self,redirect_url,status=302):
        paths = [key[0] for key in self.routes.keys()]
        if(redirect_url not in paths):
            err_res =  Response.error(message="Redirect Url Invalid",status_code=500)
            return err_res
        
        else:
            body = {"redirect_url_endpoint":redirect_url}
            res = Response(json.dumps(body),status_code=status)
            return res
    
    async def send_packet(self,writer,addr,data,route=None):
        try:
            if(self.is_edoi_node == False):
                writer.write(data)
                await writer.drain()
            else:
                if(route == None or len(route) < 2):
                    print(f"[ERROR] Failed to send packet. Route to short or none: {route}")
                    return
                count = len(route) - 2
                packet = {
                    "type": "return",
                    "route": route,
                    "count": count,
                    "payload": data.decode("utf-8"),
                    "ip_combo":(self.host,self.port)
                }
                # print(f"Server:Return:{time.time()}")

                # httpe_logging.sync_log(f"Server:Return:{time.time()}")

                try:
                    _, writer = await asyncio.open_connection(self.edoi_ip, self.edoi_port)

                    message = json.dumps(packet).encode('utf-8')
                    writer.write(message)
                    await writer.drain()

                    writer.close()
                    await writer.wait_closed()

                except Exception as e:
                    print(f"Failed to send packet to EDOI node: {e}")
                return
        except Exception as e:
            print(f"[ERROR]. General error sending packet to {addr}: {e}")
    # def edoi_net_rec()