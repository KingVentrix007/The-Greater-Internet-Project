import httpe_client



def get_fun_fact():
    url = "http://localhost:8000/fun-fact"
    
    response = httpe_client.send_request_post(path=url)
    print(response.status_code)
    print(response.json())



def main():
    username = input("Enter username")
    password = input("Enter password")
    httpe_client.init_connection(username, password,user_url="http://localhost:8000/")
    get_fun_fact()

main()