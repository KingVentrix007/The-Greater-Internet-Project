from httpe_server import Httpe
from httpe_core import Response

server =  Httpe(port=28080, server_host="127.0.0.1")


@server.path("/dashboard", method="GET")
def dashboard():
    html = open("dashboard.html", "r", encoding="utf-8").read()
    headers = {"content-type": "html"}
    return Response(html, headers=headers, status=200)


server.serve()