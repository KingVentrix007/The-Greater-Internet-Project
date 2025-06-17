# import httpe_sync
import httpe_client.httpe_sync as httpe_sync
response = httpe_sync.post(
    "edoi://HTTPE/test",
    data={"message": "Hello from sync wrapper!"}
)
print("Status:", response.status_code)
print("Response:", response.text)

response = httpe_sync.post(
    "edoi://HTTPE/test",
    data={"message": "Hello from sync wrapper. Second send!"}
)

print("Status:", response.status_code)
print("Response:", response.text)
