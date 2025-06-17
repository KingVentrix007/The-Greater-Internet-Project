import asyncio
import threading
from typing import Any
from httpe_client import HttpeClient  # your real async client
import requests
import uuid
import socket
import json

_loop = asyncio.new_event_loop()
_thread = threading.Thread(target=_loop.run_forever, daemon=True)
_thread.start()

def _run_async(coro):
    """Run async code in the background thread."""
    future = asyncio.run_coroutine_threadsafe(coro, _loop)
    return future.result()

_clients = {}
# client = httpe_client.HttpeClient(
#         port=5400,
#         connect_to_edoi=True,
#         edoi_ip='127.0.0.1',
#         edoi_port=21199,
#         edoi_target=edoi_target,
#         edoi_client_name=client_name,
#         silent_mode=True
    # )

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

async def _get_client(url: str) -> HttpeClient:
    domain = _extract_domain(url)
    # print(domain)
    if domain not in _clients:
        # Optional: configure HttpeClient differently based on domain
        # tartget = url.splt
        print("WARNING. Using EDOI-NET node port 21199 for all clients. This is not recommended for production use.")
        print("WARNING. Using EDOI-NET node IP 127.0.0.1 for all clients. This is not recommended for production use.")
        client_listening_port = find_free_port()
        _clients[domain] = HttpeClient(port=client_listening_port,edoi_target=domain,edoi_port=21199,edoi_ip='127.0.0.1',connect_to_edoi=True,silent_mode=True,edoi_client_name=str(uuid.uuid4()))
        await _clients[domain].start() # This tho is typically called using await. and connects to client to the server. So it has to be called
    return _clients[domain]


def post(url: str, data: Any = None, headers: dict = None, **kwargs):
    if url.startswith("edoi://"):
        client =  _run_async(_get_client(url))
        locations = url.split("/")
        location = "/".join(locations[3:])
        if(location[0] != "/"):
            location = "/"+location
        # print(location)
        return _run_async(client.post(location=location, body=json.dumps(data)))
    else:
        return requests.post(url, data=data, headers=headers, **kwargs)

def get(url: str, headers: dict = None, **kwargs):
    if url.startswith("edoi://"):
        client = _run_async(_get_client(url))
        return _run_async(client.get(url, headers=headers, **kwargs))
    else:
        return requests.get(url, headers=headers, **kwargs)

