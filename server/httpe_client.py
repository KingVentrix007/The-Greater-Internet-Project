import socket
import uuid
from datetime import datetime,timezone
from cryptography.fernet import Fernet
import httpe_secure as sec
import json

class HttpeResponse:
    def __init__(self, raw_response: str):
        self.raw_response = raw_response.strip()
        self.headers = {}
        self._body_str = ""
        self._token = None
        self._parse()

    def _parse(self):
        header_section, body_section = self.raw_response.split("END", 1)
        header_lines = header_section.strip().splitlines()
        self._body_str = body_section.strip()

        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                self.headers[key.strip()] = value.strip()

        self.status = self.headers.get("STATUS")
        self.content_length = int(self.headers.get("CONTENT_LENGTH", -1))

    def body(self) -> str:
        return self._body_str

    def json(self) -> dict:
        try:
            return json.loads(self._body_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in response body: {e}")

    def __repr__(self):
        return f"<HttpeResponse status={self.status} content_length={self.content_length}>"





class HttpeClient:
    def __init__(self, host="127.0.0.1", port=8080):
        self.host = host
        self.port = port
        #Privates
        self._client_id = None
        self._aes_key = None
        self._server_rsa_pub_key = None
        self._aes_key_enc = None
        self._user_id_enc = None
        self._enc_mode_active = False
        self.secure = False
    def send_request(self, method, location, headers=None, body="",use_httpe=True):
        if(self.secure == False and use_httpe == True):
            self._init_connection()
        return self._send_request_enc(method, location, headers, body)
    def _send_request_enc(self, method, location, headers=None,body=""):
        if headers is None:
            headers = {}

        # Add standard HTTPE headers
        headers.setdefault("client_id", self._client_id)
        headers.setdefault("packet_id", str(uuid.uuid4()))
        headers.setdefault("is_com_setup", False)
        headers.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        headers.setdefault("compressions", "false")
        
        request_lines_to_enc = [
            
            f"METHOD:{method.upper()}",
            f"LOCATION:{location}",
            "HEADERS:"
        ]
        for key, value in headers.items():
            request_lines_to_enc.append(f"{key}:{value}")
        request_lines_to_enc.append("END")

        if method.upper() == "POST":
            print("POST")
            request_lines_to_enc.append(body)
            request_lines_to_enc.append("END")
        request_data = "\n".join(request_lines_to_enc)
        enc_request_data = sec.fernet_encrypt(request_data,self._aes_key)
        packet_start = [
            "VERSION:HTTPE/1.0",
            "TYPE:REQ_ENC",
            f"TOKEN:{self._token}",
            f"{enc_request_data}",
            "END"
            ]
        data_to_send = "\n".join(packet_start)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            s.sendall(data_to_send.encode())
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
        #STEP 1 GET RSA PUBLIC KEY FROM SERVER
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
        #STEP 2 SEND AES KEY To SERVER, RSA encrypted
        #   Also sends ID in header
        request_lines = [
            "VERSION:HTTPE/1.0",
            "TYPE:SHARE_AES",
            "METHOD:POST",
            "HEADERS:"
        ]
        print(self._server_rsa_pub_key,"\n\n",type(self._server_rsa_pub_key))
        enc_aes_key = sec.rsa_encrypt_key(self._aes_key.encode(),(self._server_rsa_pub_key))
        enc_user_id = sec.encrypt_user_id(str(self._client_id),self._server_rsa_pub_key)
        headers = {}
        headers.setdefault("aes_key",enc_aes_key)
        headers.setdefault("user_id",enc_user_id)
        for key, value in headers.items():
            request_lines.append(f"{key}:{value}")
        request_lines.append("END")
        request_data = "\n".join(request_lines)
        parsed_response = self._connection_send(request_data)

        if(parsed_response.status != "200 OK"):
            print("Inti error")
            return #Handle errors
        enc_token = parsed_response.body()
        print(enc_token)
        self._token = enc_token
        self._aes_key_enc = enc_aes_key
        self._user_id_enc = enc_user_id
        self._enc_mode_active = True


        
            



