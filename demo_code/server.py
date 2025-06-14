import httpe_server
server = httpe_server.Httpe(debug_mode=True)


@server.path("/TEST",method="POST")
def test_end(data):
    print(data)
    return "FOOD"

server.serve()
