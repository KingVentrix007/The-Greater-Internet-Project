import httpe_client
import time
import json
client = httpe_client.HttpeClient()


def send():
    global client
    data = {"data":"12234"}
    
    print("SENDING POST request to /PTS")
    start_time = time.time()
    res = client.send_request("POST","/TEST",body=json.dumps(data))
    end_time = time.time()
    print("Time taken for POST request:", end_time - start_time, "seconds")
    # res = client.send_request("GET","/hello-world")
    print(res.status)
    # print(res.json())
send()