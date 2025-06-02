import socket
from threading import Thread
import threading
import inspect
import json
from httpe_class import _Response
from datetime import datetime, timezone, timedelta
import httpe_keys
class Httpe:
    def __init__(self,server_host="127.0.0.1",Port=8080):
        self.routes = {}
        self.host = server_host
        self.port = Port

    def path(self, route, method="GET"):
        def decorator(func):
            self.routes[(route, method)] = func
            return func
        return decorator
    def paths(self):
        for (route, method), func in self.routes.items():
            print(f"{method} {route} -> {func.__name__}")
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
    def _handle_share_aes(self,data):
        pass # Do this tmr
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
                err_res =  _Response.error(message="Internal Server Error",status="500 INTERNAL SERVER ERROR")
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
            
            reading_headers = False
            for line in lines:
                line = line.strip()
                if line.startswith("VERSION:"):
                    version = line.split(":", 1)[1].strip()
                elif line.startswith("TYPE:"):
                    is_initial_packet = True
                    initial_packet_type = line.split(":", 1)[1].strip().upper()
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
            if(is_initial_packet == True):
                if(initial_packet_type == "GET_RSA"):
                    send_rsa_pub = {"rsa":httpe_keys.get_public_key()}
                    rsa_rez = _Response(json.dumps(send_rsa_pub))
                    conn.sendall(rsa_rez.serialize().encode())
                    return
                elif(initial_packet_type == "SHARE_AES"):
                    res_data = self._handle_share_aes(headers)
            packet_id = headers.get("packet_id",None)
            if(packet_id == None):
                err_res =  _Response.error(message="packet_id missing",status="400 BAD REQUEST")
                conn.sendall(err_res.serialize().encode())
                return
            print(f"HTTPE {method} {location} from {addr} with headers {headers}")
            timestamp = headers.get("timestamp", None)
            if(timestamp == None):
                err_res =  _Response.error(message="Invalid Timestamp",status="400 BAD REQUEST")
                conn.sendall(err_res.serialize().encode())
                return
            timestamp = datetime.fromisoformat(timestamp)
            now = datetime.now(timezone.utc)
            if now - timestamp > timedelta(minutes=2):
                err_res =  _Response.error(message="Old Timestamp",status="400 BAD REQUEST")
                conn.sendall(err_res.serialize().encode())
                return
            handler = self.routes.get((location, method))

            if handler:
                sig = inspect.signature(handler)
                if(len(sig.parameters) == 0):


                    result = handler()
                    if not isinstance(result, _Response):
                        result = _Response(str(result))  # fallback
                    _Response = result.serialize()
                else:
                    result = self._parse_handler(handler,sig,json.loads(body))
                    if not isinstance(result, _Response):
                        result = _Response(str(result))  # fallback
                    _Response = result.serialize()
            else:
                result = "Route Not Found"
                if not isinstance(result, _Response):
                        result = _Response(str(result))  # fallback
                _Response = result.serialize()

            conn.sendall(_Response.encode())

        except Exception as e:
            err_res =  _Response.error(message=f"Error With Client{e}",status="400 BAD REQUEST")
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
                
                err_res =  _Response.error(message="Invalid Parameter",status="400 BAD REQUEST")
        #         # 
                return err_res
        for name, param in sig.parameters.items():
            print(name)
            if(name in body):
                kwargs[name] = body[name]
            else:
                err_res =  _Response.error(message="Invalid Parameter",status="400 BAD REQUEST")
                # 
                return err_res
        return handler(**kwargs)