# import httpe_sync
import time
import httpe_client.httpe_sync as httpe_sync
print("RUNNING SYNC WRAPPER TEST")
response = httpe_sync.post(
    "httpe://127.0.0.1:28080/dashboardsss",
    body = "",
    headers={"Content-Type": "application/json","Accepts":"application/json"},
)
print(response.text)
print(response.status_code)
print(response.status)
# print("Testing client kill")
# httpe_sync.disconnect("httpe://127.0.1:28080")
# print("Testing client restart")
# response = httpe_sync.get(
#     "httpe://127.0.1:28080/user/123/cat/food",
#     headers={"Content-Type": "text/plain"},
# )
# print(response.text)
# print(response.status_code)