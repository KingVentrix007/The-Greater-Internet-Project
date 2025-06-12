import socket
import json
from cryptography.hazmat.primitives import hashes
import uuid
import threading
import time
import inspect
class EDOIResponse:
    def __init__(self, body="", status="200 OK",status_code=200, headers=None):
        self.body = body
        # if(status ==  None):
        #     status = httpe_error.get_error_description(status_code)
        self.status = status
        self.status_code = status_code

        self.headers = headers if headers else {}

    def serialize(self):
        response_lines = [
            "RESPONSE:HTTPE/1.0",
            f"STATUS:{self.status}",
            f"STATUS_CODE:{self.status_code}",
            f"CONTENT_LENGTH:{len(self.body)}",
        ]
        for key, value in self.headers.items():
            response_lines.append(f"{key}:{value}")
        response_lines.append("END")
        response_lines.append(self.body)
        return "\n".join(response_lines)
    def error(message="Internal Server Error", status="500 INTERNAL SERVER ERROR",status_code=500):
        return Response(body=message, status=status,status_code=status_code)


class EDOIServer():
    def __init__(self,port,ip,edoi_port,edoi_ip,name) -> None:
        self.routes = {}
        # self.server_socket = None
        # self.neighbors = {}
        self.port = port # This server's port
        self.ip = ip #This server's IP
        self.name = name # This server's name
        # Encryption stuff:
        self.rsa_public_key_shared = None # RSA public key shared by this server
        self.rsa_private_key = None # RSA private key of this server, corresponds to self.rsa_public_key_shared

        #EDOI server's port and IP
        self.edoi_port = edoi_port
        self.edoi_ip = edoi_ip
        
    def serve(self):
        self._send_connect()
        time.sleep(0.5)
        threading.Thread(target=self.start_server, daemon=True).start()
        while True:
            time.sleep(0.05)
    def path(self, route, method="POST"):
        def decorator(func):
            self.routes[(route, method)] = func
            return func
        return decorator
    def _send_connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((self.edoi_ip, self.edoi_port))
            print(f"[+] Connected to EDOI node at {self.edoi_ip}:{self.edoi_port}")

            # Send a message to the EDOI node
            message = json.dumps({"type": "connect","tup":(self.ip,self.port)}).encode('utf-8')
            client_socket.sendall(message)
            
            print("[√] Message sent successfully.")
    def compute_hashed_identity(self,name:str, salt: str) -> str:
        return name
        digest = hashes.Hash(hashes.SHA256())
        digest.update((name + salt).encode())
        return digest.finalize().hex()
    def send_data(self,path,data):
        count = 1
        packet = {
            "type": "forward",
            "route": path,
            "count": count,
            "payload": data
        }
        # Send to next hop
        # next_hop = route[count]
        # print("Next hop",next_hop)
        time.sleep(1)
        message_id = packet.get("message_id",None)
        packet["message_id"] = message_id or str(uuid.uuid4())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((self.edoi_ip, self.edoi_port))
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
            # print(line)
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
    def process_client(self,return_path,data):
        lines = data.splitlines()
        headers,version,is_initial_packet,initial_packet_type,method,location,body  = self._handle_packet_contents(lines)
        if(is_initial_packet == True):
            if(initial_packet_type == "GET_RSA"):
                send_rsa_pub = {"rsa":self.rsa_public_key_shared}
                rsa_rez = EDOIResponse(json.dumps(send_rsa_pub))
                self.send_data(return_path, rsa_rez.serialize())
            elif(initial_packet_type == "SHARE_AES"):
                print("Will handle AES sharing")
        else:
            handler = self.routes.get((location, method))
            if handler:
                sig = inspect.signature(handler)
                ##! Should ONLY Use encrypted data, but is unencrypted to streamline development at the moment
                result = self._parse_handler(handler,sig,json.loads(body))
                if not isinstance(result, EDOIResponse):
                        result = EDOIResponse(str(result))  # fallback
                response = result.serialize()
                self.send_data(return_path, response)
    def _parse_handler(self,handler,sig,body):
            if(body != None):
                kwargs = {}
                for val in body.keys():
                    print(val,sig.parameters)
                    if val not in sig.parameters:
                        
                        err_res =  EDOIResponse.error(message="Invalid Parameter",status_code=400)
                #         # 
                        return err_res
                for name, param in sig.parameters.items():
                    if(name in body):
                        kwargs[name] = body[name]
                    else:
                        err_res =  EDOIResponse.error(message="Invalid Parameter",status_code=400)
                        # 
                        return err_res
                
            res_data = handler(**kwargs)
            return res_data
    def _handle_conn(self,data):
        # print(data)
        if(data.get("type") == "find"):
            route = data.get("route", None)
            target_hash = data.get("hash", None)
            if route and target_hash:
                salt = data.get("salt", None)
                name_hash = self.compute_hashed_identity(self.name, salt)
                if name_hash == target_hash:
                    route_member = {"hash":name_hash,"salt":salt}
                    route.append(route_member)
                    ret_data = {"type":"path","route":route,"count":len(route)-2,"hash":target_hash,"salt":salt}
                    ret_data["message_id"] = str(uuid.uuid4())
                    try:
                        json_str = json.dumps(ret_data)
                        encoded = json_str.encode('utf-8')

                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                            client_socket.connect((self.edoi_ip, self.edoi_port))
                            client_socket.sendall(encoded)
                    except Exception as e:
                        print(f"[!] Error sending data: {e}")
        elif(data.get("type") == "connect"):
            pass
        elif(data.get("type") == "return"):
            print("data:",data)
        elif(data.get("type") == "forward"):
            # print(data.keys())
            count = data.get("count",None)
            route = data.get("route",None)
            end_point = route[count]
            salt = route[count]["salt"]

            end_hash = end_point.get("hash",None)
            my_hash = self.compute_hashed_identity(self.name,salt)
            if(my_hash == end_hash):
                payload = data.get("payload",None)
                self.process_client(route, payload)
                print(payload)

                
            # pass
    def start_server(self):
         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', int(self.port)))
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
                        # neighbors[addr] = None
                        self._handle_conn(json_data)
                        
                        # print(f"[√] Received JSON: {json_data}")
                    except json.JSONDecodeError as e:
                        print(f"[!]JSON decode error: {e}")
                    except Exception as e:
                        print(f"[!]General error: {e}")
                    finally:
                        pass
                        # print("[*] Connection closed.\n")

node = EDOIServer(5400,'127.0.0.1',5199,'127.0.0.1',"TestNode")