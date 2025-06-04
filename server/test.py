


import httpe_client
import json
client = httpe_client.HttpeClient()
cleint2 = httpe_client.HttpeClient()
data = {"data":"12234"}

res = client.send_request("POST","/PTS",body=json.dumps(data))
print(res.status)
print(res.json())
data = {"data":"456"}

res2 = cleint2.send_request("POST","/PTS",body=json.dumps(data))
print(res2.status)
print(res2.json())


# data = {"data":"45622"}
# res = client.send_request("POST","/PTS",body=data)
# print(res.status)
# print(res.json())