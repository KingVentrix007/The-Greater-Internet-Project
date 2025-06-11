


import httpe_client
import json
client = httpe_client.HttpeClient(port=5400,connect_to_edoi=True,edoi_ip='127.0.0.1',edoi_port=5199,edoi_target="HTTPE",edoi_client_name="TestC")
# cleint2 = httpe_client.HttpeClient()
data = {"data":"12234"}

res = client.send_request("POST","/PTS",body=json.dumps(data))
# res = client.send_request("GET","/hello-world")
print(res.status)
print(res.json())
