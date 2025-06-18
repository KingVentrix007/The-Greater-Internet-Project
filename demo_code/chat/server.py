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

@server.path("/get_test",method="GET")
def get_test():
    return  {"status": "Message received successfully"}
# server.paths()
server.serve()