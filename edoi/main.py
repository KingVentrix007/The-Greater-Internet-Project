from httpe_server import Httpe

server = Httpe(use_edoi_node=True,edoi_ip='127.0.0.1',edoi_port=5122,name="HTTPE")
@server.path("/hello-world",method="GET")
def test_get():
    return "cat fish"

@server.path("/PTS",method="POST")
def test_post(data):
    body = {"ret":data}
    return body
@server.path("/PTS2",method="POST")
def pts2(data):
    return data


server.paths()
server.serve()