import httpe_server
server = httpe_server.Httpe()


@server.path("/TEST",method="POST")
def test_end(data):
    print(data)
    return "FOOD"

server.serve()
