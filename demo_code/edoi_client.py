


import httpe_client
import json
import time
import asyncio

# cleint2 = httpe_client.HttpeClient()
client = httpe_client.HttpeClient(port=5400,connect_to_edoi=True,edoi_ip='127.0.0.1',edoi_port=20199,edoi_target="HTTPE",edoi_client_name="TestC")

async def send():

    # global client
    print("Starting up client...")
    await client.start()
    print("Beginning code execution...")
    data = {"data":"12234"}
    
    print("SENDING POST request to /PTS")
    start_time = time.time()
    res = await client.send_request("POST","/PTS",body=json.dumps(data))
    end_time = time.time()
    print("Time taken for POST request:", end_time - start_time, f"seconds. Start: {start_time}")
    # res = client.send_request("GET","/hello-world")
    print(res.status)
    print(res.json())
    return end_time-start_time
asyncio.run(send())
# send()