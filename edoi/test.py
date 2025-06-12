


import httpe_client
import json
import time
client = httpe_client.HttpeClient(port=5400,connect_to_edoi=True,edoi_ip='127.0.0.1',edoi_port=20193,edoi_target="HTTPE",edoi_client_name="TestC")
# cleint2 = httpe_client.HttpeClient()

def send():
    global client
    data = {"data":"12234"}
    
    print("SENDING POST request to /PTS")
    start_time = time.time()
    res = client.send_request("POST","/PTS",body=json.dumps(data))
    end_time = time.time()
    print("Time taken for POST request:", end_time - start_time, "seconds")
    # res = client.send_request("GET","/hello-world")
    print(res.status)
    print(res.json())

send()