import server

app = server.EDOIServer(5400,"127.0.0.1",5199,"127.0.0.1","MyServer")

@app.path("/test", method="POST")
def end_point_test(data):
    print("Received data:", data)
    return "Response from end_point_test"

app.serve()
#TODO: Make a client that can connect to this server and send data to the /test endpoint