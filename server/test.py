import socket
import uuid
from datetime import datetime,timezone
from cryptography.fernet import Fernet
from httpe_class import HttpeResponse
import httpe_secure as sec
class HttpeClient:
    def __init__(self, host="127.0.0.1", port=8080):
        self.host = host
        self.port = port
        #Privates
        self._client_id = None
        self._aes_key = None
        self._server_rsa_pub_key = None
    def send_request(self, method, location, headers=None, body=""):
        if headers is None:
            headers = {}

        # Add standard HTTPE headers
        headers.setdefault("client_id", "None")
        headers.setdefault("token", "None")
        headers.setdefault("packet_id", str(uuid.uuid4()))
        headers.setdefault("is_com_setup", False)
        headers.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        headers.setdefault("compressions", "false")

        request_lines = [
            "VERSION:HTTPE/1.0",
            f"METHOD:{method.upper()}",
            f"LOCATION:{location}",
            "HEADERS:"
        ]
        for key, value in headers.items():
            request_lines.append(f"{key}:{value}")
        request_lines.append("END")

        if method.upper() == "POST":
            print("POST")
            request_lines.append(body)
            request_lines.append("END")

        request_data = "\n".join(request_lines)
        print(request_data)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(request_data.encode())
            response = self._receive_full_response(s)
            ret_res = HttpeResponse(response)
            return ret_res

    def _receive_full_response(self, s):
        chunks = []
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks).decode()
    def _connection_send(self,request_data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(request_data.encode())
            response = self._receive_full_response(s)
            parsed_response = HttpeResponse(response)
            # json_data = parsed_response.json()
            return parsed_response
    def _init_connection(self):
        self._client_id = uuid.uuid4()
        self._aes_key = Fernet.generate_key().decode('utf-8')
        request_lines = [
            "VERSION:HTTPE/1.0",
            "TYPE:GET_RSA",
            "METHOD:POST",
        ]
        request_lines.append("END")
        request_data = "\n".join(request_lines)

        parsed_response = self._connection_send(request_data)
        json_data = parsed_response.json()
        self._server_rsa_pub_key = json_data.get("rsa",None)
        if(self._server_rsa_pub_key == None):
            # Handle error
            return
        request_lines = [
            "VERSION:HTTPE/1.0",
            "TYPE:SHARE_AES",
            "METHOD:POST",
            "HEADERS"
        ]
        enc_aes_key = sec.rsa_encrypt_key(self._aes_key,self._server_rsa_pub_key)
        enc_user_id = sec.fernet_encrypt(str(self._client_id),self._aes_key.encode("utf-8"))
        headers = {}
        headers.setdefault("aes",enc_aes_key)
        headers.setdefault("user_id",enc_user_id)
        for key, value in headers.items():
            request_lines.append(f"{key}:{value}")
        request_lines.append("END")
        request_data = "\n".join(request_lines)
        parsed_response = self._connection_send(request_data)


        
            



import json
client = HttpeClient()

# Simple GET
response = client._init_connection()