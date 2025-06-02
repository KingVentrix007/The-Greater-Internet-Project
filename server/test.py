import socket
import uuid
from datetime import datetime,timezone

class HttpeClient:
    def __init__(self, host="127.0.0.1", port=8080):
        self.host = host
        self.port = port

    def send_request(self, method, location, headers=None, body=""):
        if headers is None:
            headers = {}

        # Add standard HTTPE headers
        headers.setdefault("client_id", "None")
        headers.setdefault("token", "None")
        headers.setdefault("packet_id", str(uuid.uuid4()))
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
            return response

    def _receive_full_response(self, s):
        chunks = []
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks).decode()


import json
client = HttpeClient()

# Simple GET
response = client.send_request("GET", "/hello-world")


print("GET Response:\n", response)

body = {"data":"hello world","cat":"cool"}
body = json.dumps(body)
response = client.send_request("POST", "/PTS",body=body)
print("POST Response:\n",response)
