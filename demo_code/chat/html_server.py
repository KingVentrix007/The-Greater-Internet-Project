from httpe_server import Httpe
from httpe_core import Response

server =  Httpe(port=28080, server_host="127.0.0.1")


@server.route("/dashboard", methods=[])
async def dashboard():
    html = open("dashboard.html", "r", encoding="utf-8").read()
    headers = {"content-type": "html"}
    return html,200

@server.route("/user/{id}/cat/{plan}", methods=["POST","GET"])
async def get_user(id, plan):
    user_id = id
    plan = plan
    print(f"User ID: {user_id}, Plan: {plan}")
    # print(user_id)
    return Response(f"User ID: {user_id}", status=200)

server.start()