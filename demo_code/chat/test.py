# import httpe_sync
import time
import httpe_client.httpe_sync as httpe_sync
print("RUNNING SYNC WRAPPER TEST")
response = httpe_sync.get(
    "httpe://127.0.1:28080/dashboard",
    headers={"Content-Type": "application/json","Accepts":"text/html"},
)
print(response.text)
print(response.status_code)
print("Testing client kill")
httpe_sync.disconnect("httpe://127.0.1:28080")
print("Testing client restart")
response = httpe_sync.get(
    "httpe://127.0.1:28080/user/123/cat/food",
    headers={"Content-Type": "text/plain"},
)
print(response.text)
print(response.status_code)