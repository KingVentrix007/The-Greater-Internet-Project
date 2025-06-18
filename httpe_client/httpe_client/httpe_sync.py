import asyncio
import threading
from typing import Any
from httpe_client import HttpeClient  # your real async client
import requests
import uuid
import socket
import json
import re
from urllib.parse import urlparse
import atexit

_loop = asyncio.new_event_loop()
_thread = threading.Thread(target=_loop.run_forever, daemon=True)
_thread.start()

def _run_async(coro):
    """Run async code in the background thread."""
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result()

_clients = {}

def find_free_port(start_port=22100, end_port=65535, host='127.0.0.1'):
    for port in range(start_port, end_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free ports available in the given range.")

def _extract_domain(url: str) -> str:
    return url.split("/")[2]  # naive domain extractor
def extract_ip_port(url: str, default_ip="127.0.0.1", default_port=28080):
    try:
        parsed = urlparse(url)
        if not parsed.scheme:  # in case scheme is missing, try adding dummy
            parsed = urlparse("httpe://" + url)

        # Extract host and port
        host = parsed.hostname
        port = parsed.port

        # Simple IP address regex
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

        if host and re.match(ip_pattern, host) and port:
            return host, port
    except Exception:
        pass

    return default_ip, default_port
async def _get_client(url: str,type:str="httpe") -> HttpeClient:
    domain = _extract_domain(url)
    # print(domain)
    if domain not in _clients:
        # Optional: configure HttpeClient differently based on domain
        # tartget = url.splt
        if type == "edoi":
            print("WARNING. Using EDOI-NET node port 21199 for all clients. This is not recommended for production use.")
            print("WARNING. Using EDOI-NET node IP 127.0.0.1 for all clients. This is not recommended for production use.")
            client_listening_port = find_free_port()
            _clients[domain] = HttpeClient(port=client_listening_port,edoi_target=domain,edoi_port=21199,edoi_ip='127.0.0.1',connect_to_edoi=True,silent_mode=True,edoi_client_name=str(uuid.uuid4()))
        elif type == "httpe":
            print("Haven't implemented EDOI-HTTPE DNS resolution yet. The port and IP will try to be extracted from the URL.")
            # Extract host and port from the URL
            host,port = extract_ip_port(url)
            
            _clients[domain] = HttpeClient(host=host, port=port, connect_to_edoi=False, silent_mode=True)
        await _clients[domain].start() # This tho is typically called using await. and connects to client to the server. So it has to be called
    return _clients[domain]


def post(url: str, data: Any = None, headers: dict = None, **kwargs):
    if url.startswith("edoi://"):
        client =  _run_async(_get_client(url),"edoi")
        locations = url.split("/")
        location = "/".join(locations[3:])
        if(location[0] != "/"):
            location = "/"+location
        # print(location)
        return _run_async(client.post(location=location, body=json.dumps(data)))
    elif url.startswith("httpe://"):
        client =  _run_async(_get_client(url),"httpe")
        locations = url.split("/")
        location = "/".join(locations[3:])
        if(location[0] != "/"):
            location = "/"+location
        # print(location)
        return _run_async(client.post(location=location, body=json.dumps(data)))
    else:
        return requests.post(url, data=data, headers=headers, **kwargs)

def disconnect(url: str):
    """Disconnects the client associated with the given URL."""
    domain = _extract_domain(url)
    if domain in _clients:
        client = _clients[domain]
        _run_async(client.disconnect())
        del _clients[domain]
    else:
        print(f"No client found for {url}.")

def get(url: str, headers: dict = None, **kwargs):
    if url.startswith("edoi://"):
        locations = url.split("/")
        location = "/".join(locations[3:])
        if(location[0] != "/"):
            location = "/"+location
        client = _run_async(_get_client(url),type="edoi")
        return _run_async(client.get(location=location, headers=headers))
    elif url.startswith("httpe://"):
        client =  _run_async(_get_client(url,type="httpe"))
        locations = url.split("/")
        location = "/".join(locations[3:])
        if(location[0] != "/"):
            location = "/"+location
        # print(location)
        return _run_async(client.get(location=location, headers=headers))
    else:
        return requests.get(url, headers=headers, **kwargs)

def _on_exit():
    """Cleanup function to close all clients."""
    for client in _clients.values():
        _run_async(client.disconnect())
atexit.register(_on_exit)