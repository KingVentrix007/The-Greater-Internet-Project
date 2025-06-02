def send_request_post(request,path):
    url = f"http://localhost:8000/{path}" 
    enc_request = keys.encrypt_for_url(request,base64.b64encode((keys.get_global_aes_key())))
    payload = {"request_data":enc_request}
    headers = {"Authorization": f"Bearer {keys.get_token()}"}
    response = requests.post(url, json=payload,headers=headers)
    return response

def test_req():
    payload = {"username":"tristan"}
    res = send_request_post(payload,"test")
    print(res.status_code)
    print(res.json())
init_connection()
test_req()