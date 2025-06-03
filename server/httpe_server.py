import os
import socket
from threading import Thread
import threading
import inspect
import json
from httpe_class import Response
from datetime import datetime, timezone, timedelta
import httpe_keys
import httpe_secure as sec
import uuid
import base64
import httpe_cert
class Httpe:
    def __init__(self,server_host="127.0.0.1",Port=8080):
        self.routes = {}
        self.host = server_host
        self.port = Port
        self.valid_token_ids = []
        self.valid_token_ids_per_user = {}


    def path(self, route, method="GET",requires_enc=True):
        def decorator(func):
            self.routes[(route, method,requires_enc)] = func
            return func
        return decorator
    def paths(self):
        for (route, method, requires_enc), func in self.routes.items():
            enc_status = "Encrypted" if requires_enc else "Unencrypted"
            print(f"{method} {route} ({enc_status}) -> {func.__name__}")
    def serve(self, host="127.0.0.1", port=8080):
        print(f"HTTPE server running on {host}:{port}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            s.settimeout(1.0)  # <-- check every 1 second for interrupt

            try:
                while True:
                    try:
                        conn, addr = s.accept()
                        threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue  # Allows checking for KeyboardInterrupt
            except KeyboardInterrupt:
                print("\nShutting down HTTPE server...")
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
            aes_key = sec.rsa_decrypt_key(aes_key_enc,httpe_keys.get_private_key(True))
            user_id = sec.decrypt_user_id(user_id_enc,httpe_keys.get_private_key(True))
            token = self._create_token(user_id)
            token_enc = sec.fernet_encrypt(json.dumps(token),httpe_keys.get_master_key())
            certificate = httpe_cert.create_corticate(self.host,10,httpe_keys.get_public_key(True))
            certificate_enc = sec.fernet_encrypt(json.dumps(certificate),aes_key)
            ret_data = {"token":token_enc,"certificate":certificate_enc}

            httpe_keys.set_user_key(aes_key,user_id)
            res = Response(json.dumps(ret_data))
            return res
        except Exception as e:
            print(e)
    def _handle_enc_request(self,data:str):
        user_id_enc = None
        aes_key_to_use = None
        found_id = False
        enc_data = None
        for line in data:
            if line.startswith("TOKEN:"):
                enc_token = line.split(":", 1)[1].strip()
                try:
                    plain_token = sec.fernet_decrypt(enc_token,httpe_keys.get_master_key())
                    json_token = json.loads(plain_token)
                except Exception as e:
                    print(e)
                    return None
                # print(json_token)
                user_id = json_token["user_id"]
                if(self._validate_token(json_token,user_id) == False):
                    print("NONE")
                    return None
                aes_key_to_use = httpe_keys.get_user_key(user_id)
                found_id = True
            elif(found_id == True):
                enc_data = line
                break
        decrypted_data = sec.fernet_decrypt(enc_data,aes_key_to_use)
        # print(decrypted_data)
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
    def _handle_client(self, conn, addr):
        try:
            try:
                data = b""
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    # print(chunk)
                    if b"END\n" in data or b"END\r\n" in data or b"END" in data:
                        break
                
            except Exception as e:
                err_res =  Response.error(message="Internal Server Error",status="500 INTERNAL SERVER ERROR")
                conn.sendall(err_res.serialize().encode())
                return
            # print(type(data))
            text = data.decode()
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
            # print(text)
            reading_headers = False
            headers,version,is_initial_packet,initial_packet_type,method,location,body  = self._handle_packet_contents(lines)
            if(is_initial_packet == True):
                if(initial_packet_type == "GET_RSA"):
                    send_rsa_pub = {"rsa":httpe_keys.get_public_key()}
                    rsa_rez = Response(json.dumps(send_rsa_pub))
                    conn.sendall(rsa_rez.serialize().encode())
                    return
                elif(initial_packet_type == "SHARE_AES"):
                    # print(headers)
                    res_data = self._handle_share_aes(headers)
                    conn.sendall(res_data.serialize().encode())
                    return
                elif(initial_packet_type == "REQ_ENC"):
                    new_lines,user_id_from_token =  self._handle_enc_request(lines)
                    new_lines = new_lines.splitlines()
                    is_encrypted_packet = True
                    headers,version,is_initial_packet,initial_packet_type,method,location,body  =self._handle_packet_contents(new_lines)
            packet_id = headers.get("packet_id",None)
            header_user_id = headers.get("client_id",None)
            if(str(header_user_id) != str(user_id_from_token)):
                err_res =  Response.error(message="STOLEN TOKEN",status="400 BAD STOLEN")
                conn.sendall(err_res.serialize().encode())
                return
            if(packet_id == None):
                err_res =  Response.error(message="packet_id missing",status="400 BAD REQUEST")
                conn.sendall(err_res.serialize().encode())
                return
            print(f"HTTPE {method} {location} from {addr} with headers {headers}")
            timestamp = headers.get("timestamp", None)
            if(timestamp == None):
                err_res =  Response.error(message="Invalid Timestamp",status="400 BAD REQUEST")
                conn.sendall(err_res.serialize().encode())
                return
            timestamp = datetime.fromisoformat(timestamp)
            now = datetime.now(timezone.utc)
            if now - timestamp > timedelta(minutes=2):
                err_res =  Response.error(message="Old Timestamp",status="400 BAD REQUEST")
                conn.sendall(err_res.serialize().encode())
                return
            handler = self.routes.get((location, method,is_encrypted_packet))

            if handler:
                sig = inspect.signature(handler)
                if(len(sig.parameters) == 0):


                    result = handler()
                    if not isinstance(result, Response):
                        result = Response(str(result))  # fallback
                    response = result.serialize()
                else:
                    result = self._parse_handler(handler,sig,json.loads(body))
                    if not isinstance(result, Response):
                        result = Response(str(result))  # fallback
                    response = result.serialize()
            else:
                result = "Route Not Found"
                if not isinstance(result, Response):
                        result = Response(str(result))  # fallback
                response = result.serialize()

            conn.sendall(response.encode())

        except Exception as e:
            err_res =  Response.error(message=f"Error With Client{e}",status="400 SYSTEM ERROR")
            conn.sendall(err_res.serialize().encode())
            return
        finally:
            conn.close()
    def _parse_handler(self, handler,sig,body):
        # for name, param in sig.parameters.items():
        #     print(name, param.default, param.kind) 
        kwargs = {}
        for val in body.keys():
            print(val,sig.parameters)
            if val not in sig.parameters:
                
                err_res =  Response.error(message="Invalid Parameter",status="400 BAD REQUEST")
        #         # 
                return err_res
        for name, param in sig.parameters.items():
            print(name)
            if(name in body):
                kwargs[name] = body[name]
            else:
                err_res =  Response.error(message="Invalid Parameter",status="400 BAD REQUEST")
                # 
                return err_res
        return handler(**kwargs)