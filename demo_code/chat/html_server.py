from httpe_server import Httpe
from httpe_core import Response

server = Httpe(use_edoi_node=True,edoi_ip='127.0.0.1',edoi_port=21019,name="HTTPE",debug_mode=True)


@server.path("/dashboard", method="POST")
def dashboard():
    html = open("dashboard.html", "r", encoding="utf-8").read()
    headers = {"content-type": "html"}
    return Response(html, headers=headers, status=200)


server.serve()