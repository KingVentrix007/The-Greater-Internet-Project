


import httpe_client
import json
client = httpe_client.HttpeClient()

data = {"data":"12234"}

res = client.send_request("POST","/PTS",body=json.dumps(data))
