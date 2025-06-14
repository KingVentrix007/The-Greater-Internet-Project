import httpe_client
import time
import json
start_runtime = time.time()
client = httpe_client.HttpeClient(debug_mode=True)
end_runtime = time.time()

def send():
    global client
    data = {"data":"12234"}
    
    # print("SENDING POST request to /PTS")
    start_time = time.time()
    res = client.send_request("POST","/TEST",body=json.dumps(data))
    end_time = time.time()
    # print("Time taken for POST request:", end_time - start_time, "seconds")
    # file = open("avg.txt","a")
    # file.write(f"{end_time - start_time}\n")
    # file.close()
    # res = client.send_request("GET","/hello-world")
    # print(res.status)
    # print(res.json())
    return end_time - start_time


avg = 0
for i in range(0,1000):
    avg+=send()
print("Average time of packets",avg/100)

# print("Time taken for client server com:",(end_runtime-start_runtime))