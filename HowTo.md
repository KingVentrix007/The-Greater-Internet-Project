
## **HTTPE\_Server: V1.0.0**

`HTTPE_Server` runs using `asyncio` and supports both normal and EDOI modes of operation.

---

### **Creating a Server**

```python
server = Httpe(
    server_host="127.0.0.1",
    port=8080,
    running_version="V1.0.0",
    crte_file_path="cert.crte",
    key_dir_path="keys/",
    debug_mode=True
)

@server.path("/endpoint", method="GET")
async def endpoint():
    return "Hello, HTTPE!"

server.start()
```

---

### **Server Parameters**

| Parameter         | Type   | Description                                                                               |
| ----------------- | ------ | ----------------------------------------------------------------------------------------- |
| `server_host`     | `str`  | **Normal & EDOI Mode:** IP address the server binds to. Default: `"127.0.0.1"`            |
| `port`            | `int`  | **Normal Mode:** Port to listen on. Default: `8080`                                       |
| `running_version` | `str`  | Version identifier for the server                                                         |
| `crte_file_path`  | `str`  | Path to SSL certificate file (used in both normal and EDOI modes). Default: `"cert.crte"` |
| `key_dir_path`    | `str`  | Directory path where SSL or encryption keys are stored                                    |
| `debug_mode`      | `bool` | Enables verbose logging and error output when set to `True`                               |

---

### **Defining Routes**

Use `@server.path("/your_path", method="HTTP_METHOD")` to define endpoints.
Supported methods include `"GET"` or `"POST"` .

Example:

```python
@server.path("/status", method="GET")
async def status():
    return {"status": "OK"}
```

## **HTTPE\_Client: V1.0.0**

HTTPE provides two client interfaces:

### ✅ **1. Async Client** (`httpe_client.HttpeClient`)

* Full asyncio-compatible implementation.
* Use when building event-loop-driven applications or services.
* In **EDOI-NET mode**, the first request may take up to **8 seconds** due to secure authentication and handshake.

### ✅ **2. Sync Wrapper** (`httpe_client.httpe_sync`)

* Synchronous API with `requests`-like syntax.
* Can be used as a **drop-in replacement** for `requests.get`/`requests.post`.
* Automatically falls back to `requests` if the URL is not handled by HTTPE/EDOI.

---

### **Creating an Async Client**

```python
from httpe_client import HttpeClient

client = HttpeClient(
    port=5400,
    connect_to_edoi=True,
    edoi_ip="127.0.0.1",
    edoi_port=21199,
    edoi_target="TARGET_IDENTIFIER",
    edoi_client_name="MY_CLIENT_NAME",
    silent_mode=True
)

await client.start()
```
---

| Parameter                                | Type            | Description                                                                                                                   |
| ---------------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `host`                                   | `str`           | **Normal Mode:** IP address of the server. <br> **EDOI Mode:** IP address to bind the client listener. Default: `"127.0.0.1"` |
| `port`                                   | `int`           | **Normal Mode:** Port to connect to on the server. <br> **EDOI Mode:** Port to listen on locally. **Required**                |
| `connect_to_edoi`                        | `bool`          | Whether to connect through the EDOI-NET. Enables secure, anonymous routing.                                                   |
| `edoi_ip`                                | `str`           | **EDOI Mode:** IP address of the EDOI entry node to connect to.                                                               |
| `edoi_port`                              | `int`           | **EDOI Mode:** Port of the EDOI entry node.                                                                                   |
| `edoi_target`                            | `str`           | **EDOI Mode:** Final destination the client wants to reach via the EDOI network.                                              |
| `edoi_client_name`                       | `str`           | **EDOI Mode:** Unique identifier for the client within the EDOI network.                                                      |
| `silent_mode`                            | `bool`          | If `True`, suppresses logs and output messages.                                                                               |
| `pem_path` / `pubkey` / `cert` / `token` | `str` or `None` | Reserved for future use (e.g., authentication, encryption). Currently optional.                                               |

---

### **Sending a Request (Async)**

```python
response = await client.send_request(
    method="POST",
    location="/some/api/endpoint",
    body={"message": "Hello"},
    headers={"Content-Type": "application/json"}
)
```

#### Parameters for `send_request(...)`:

| Parameter  | Type            | Description                        |
| ---------- | --------------- | ---------------------------------- |
| `method`   | `str`           | `"GET"` or `"POST"`                |
| `location` | `str`           | Endpoint path (e.g. `"/api/test"`) |
| `body`     | `dict/str/None` | Request payload (optional)         |
| `headers`  | `dict/None`     | Optional headers                   |

---

### **Using the Sync Wrapper**

```python
import httpe_client.httpe_sync as httpe_sync

response = httpe_sync.post(
    "edoi://HTTPE/test",
    data={"message": "Hello world"},
    headers={
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
)

print(response.text)
print(response.status_code)
```

* Works just like `requests.post()` or `requests.get()`.
* If the URL starts with `edoi://`, the request is routed via EDOI.
* Otherwise, falls back to standard `requests`.

