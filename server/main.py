from httpe_server import Httpe

server = Httpe()
@server.path("/hello-world",method="GET")
def test_get():
    return "cat fish"

@server.path("/PTS",method="POST")
def test_post(data):
    return server.redirect("/PTS2")
@server.path("/PTS2",method="POST")
def pts2(data):
    return data


server.paths()
server.serve()