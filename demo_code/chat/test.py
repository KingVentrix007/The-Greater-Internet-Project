# import httpe_sync
import time
import httpe_client.httpe_sync as httpe_sync
print("RUNNING SYNC WRAPPER TEST")
response = httpe_sync.get(
    "httpe://127.0.1:28080/dashboard",
    headers={"Content-Type": "application/json"},
)
print(response.text)
print(response.status_code)