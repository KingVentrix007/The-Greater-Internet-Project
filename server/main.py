from httpe_server import Httpe

server = Httpe()
@server.path("/hello-world",method="GET")
def test_get():
    return "cat fish"

@server.path("/PTS",method="POST")
def test_post(data):
    print(f"{data}")
    return data


server.paths()
server.serve()