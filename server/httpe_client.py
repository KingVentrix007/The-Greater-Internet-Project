import socket
import uuid
from datetime import datetime, timezone
import httpe_secure as sec  # Must have fernet_encrypt, fernet_decrypt, rsa_encrypt_key, encrypt_user_id
import httpe_cert           # Must have verify_cert(cert, host, pem_path, pubkey)
import json
import httpe_fernet
import base64
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

    def __init__(self, host="127.0.0.1", port=8080):
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

    def send_request(self, method, location, headers=None, body="", use_httpe=True):
        """Send an encrypted request to the server, establishing connection if needed"""
        try:
            if not self.secure and use_httpe:
                self._init_connection()
            return self._send_request_enc(method, location, headers, body)
        except Exception as e:
            print(f"Error in send_request: {e}")
            return None

    def _send_request_enc(self, method, location, headers=None, body=""):
        # print(type(body),"|",type(""))
        if(type(body) != type("")):
            raise TypeError(f"Body must be of type str, current type is {type(body)}")
        """Send an encrypted packet after key exchange"""
        if headers is None:
            headers = {}

        try:
            headers.setdefault("client_id", str(self._client_id))
            headers.setdefault("packet_id", str(uuid.uuid4()))
            headers.setdefault("is_com_setup", False)
            headers.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            headers.setdefault("compressions", "false")

            request_lines = [f"METHOD:{method.upper()}", f"LOCATION:{str(location)}", "HEADERS:"]
            request_lines += [f"{str(k)}:{str(v)}" for k, v in headers.items()]
            request_lines.append("END")

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
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((self.host, self.port))
                    s.sendall(full_data.encode())
                    response = self._receive_full_response(s)
            except Exception as e:
                print(f"_send_request_enc send error {e}")

            res = HttpeResponse(response)
            # decrypted_body = sec.fernet_decrypt(res.body(), self._aes_key)
            # print(res.body())
            # print(res.status_code)
            # print(res._body_str)
            try:
                
                decrypted_body = self._fernet_class.decrypt(res.body()).decode()
            except Exception as e:
                print(f"Error in decrypted_body {e}")
            res._set_body(decrypted_body)
            return res
        except Exception as e:
            print(f"Error in _send_request_enc: {e}")
            return None

    def _receive_full_response(self, s: socket.socket) -> str:
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

    def _connection_send(self, request_data: str) -> HttpeResponse:
        """Sends a raw request and returns parsed response"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                s.sendall(request_data.encode())
                response = self._receive_full_response(s)
            return HttpeResponse(response)
        except Exception as e:
            print(f"Connection send failed: {e}")
            return None

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
                "END"
            ]
            aes_request = "\n".join(request_lines)
            response = self._connection_send(aes_request)

            if not response or not response.ok:
                print("Server rejected AES key sharing.")
                return

            response_data = response.json()
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
