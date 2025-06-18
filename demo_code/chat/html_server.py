from httpe_server import Httpe
from httpe_core import Response

server =  Httpe(port=28080, server_host="127.0.0.1")


@server.path("/dashboard", method="GET")
async def dashboard():
    html = open("dashboard.html", "r", encoding="utf-8").read()
    headers = {"content-type": "html"}
    return Response(html, headers=headers, status=200)

@server.path("/user/{id}/cat/{plan}", method="GET")
async def get_user(data, user_key=None):
    user_id = data["id"]
    plan = data["plan"]
    print(f"User ID: {user_id}, Plan: {plan}")
    # print(user_id)
    return Response(f"User ID: {user_id}", status=200)

server.start()