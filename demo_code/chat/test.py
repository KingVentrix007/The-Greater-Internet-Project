# import httpe_sync
import time
import httpe_client.httpe_sync as httpe_sync
time.sleep(1)
print("RUNNING SYNC WRAPPER TEST")
response = httpe_sync.post(
    "edoi://HTTPE/test",
    data={"message": "Hello from sync wrapper!"}
)
print("Status:", response.status_code)
print("Response:", response.text)

response = httpe_sync.post(
    "https://google.com",
    data={"message": "Hello from sync wrapper. Second send!"}
)

print("Status:", response.status_code)
print("Response:", response.text)
