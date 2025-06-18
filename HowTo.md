HTTPE_Server: V1.0.0

Creating a server:
server = Httpe()

def __init__(self,server_host="127.0.0.1",port=8080,running_version="1.0",crte_file_path="cert.crte",key_dir_path=".",name="edoi node",use_edoi_node=False,edoi_ip=None,edoi_port=None,debug_mode=False):

creating endpoints:
NOT methods,method, SUPPORTS either GET or POST
@server.path("endpoint",method="")
def function(paramter)

if Content-Type in request is application/json. Data is automaticlly parsed to function parmaters
Otherwise is passed as one value.

Respose type:
class Response:
    def __init__(self, body="", status="200 OK",status_code=200, headers=None):
        self.body = body
        # if(status ==  None):
        #     status = httpe_error.get_error_description(status_code)
        self.status = status
        self.status_code = status_code

        self.headers = headers if headers else {}

    def serialize(self):
        response_lines = [
            "RESPONSE:HTTPE/1.0",
            f"STATUS:{self.status}",
            f"STATUS_CODE:{self.status_code}",
            f"CONTENT_LENGTH:{len(self.body)}",
        ]
        for key, value in self.headers.items():
            response_lines.append(f"{key}:{value}")
        response_lines.append("END")
        response_lines.append(self.body)
        return "\n".join(response_lines)
    def error(message="Internal Server Error", status="500 INTERNAL SERVER ERROR",status_code=500):
        return Response(body=message, status=status,status_code=status_code)


run server with server.serve()


EXAMPLE:

from httpe_server import Httpe

server = Httpe(use_edoi_node=True,edoi_ip='127.0.0.1',edoi_port=21019,name="HTTPE",debug_mode=True)

@server.path('/get_message', method='POST')
def get_message(password):
    """
    Handle GET message requests.
    Expects a JSON body with a 'password' field.
    """
    # password = request.json.get('password')
    
    if not password:
        return {"error": "Password is required"}, 400
    
    # Simulate fetching a message based on the password
    message = f"Message for password: {password}"
    
    return {"message": message}, 200

@server.path('/test',method='POST')
def test_func(message):
    print(f"Test function called with message: {message}")
    return {"status": "Test function executed successfully"}

@server.path('/send_message', method='POST')
def send_message(message,password):
    """
    Handle sending messages.
    Expects a JSON body with 'message' and optional 'password'.
    """
    # data = request.json
    # message = data.get('message')
    # password = data.get('password', '')

    if not message:
        return {"error": "Message is required"}, 400

    # Simulate storing the message
    print(f"Received message: {message} with password: {password}")

    return {"status": "Message received successfully"}, 200
# server.paths()
server.serve()