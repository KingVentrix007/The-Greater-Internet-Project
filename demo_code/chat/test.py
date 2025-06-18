# import httpe_sync
import time
import httpe_client.httpe_sync as httpe_sync
print("RUNNING SYNC WRAPPER TEST")
response = httpe_sync.get(
    "edoi://HTTPE/get_test"
)
print(response.text)
print(response.status_code)