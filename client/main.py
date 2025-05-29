import handle_cert
import keys
import base64
import requests

def init_connection():
    # Step 1, get cert+rsa pub key
    server_cert = handle_cert.request_certificate()
    if server_cert is None:
        raise Exception("Failed to get certificate")
    trusted_rsa_key = handle_cert.load_trusted_root_pubkey()
    try:
        cert_valid = handle_cert.verify_certificate(server_cert,trusted_rsa_key)
    except Exception as e:
        raise Exception("Error" % e)
    if(cert_valid == False):
        raise Exception("Certificate is invalid")
    try:
        # server_public_key = keys.load_public_key(server_cert['public_key'])
        key_der = base64.b64decode(server_cert['public_key'].encode('utf-8'))
        server_public_key = keys.load_public_key(key_der)
    except KeyError:
        raise Exception("Failed to get public key")
    
    #Step 2, get AES key+RSA pair and username+password
    aes_key = keys.generate_aes_key()
    priv_key, pub_key = keys.generate_rsa_keypair()
    

    pub_pem = keys.serialize_public_key(pub_key)
    encrypted_aes_key = keys.encrypt_aes_key_with_rsa_public(aes_key, server_public_key)
    username = "tristan"
    password = "tristan"
    username_enc = keys.encrypt_string_with_aes(aes_key,username)
    password_enc = keys.encrypt_string_with_aes(aes_key,password)
    payload = {"username":username_enc,"password":password_enc,"aes_key":encrypted_aes_key,"rsa_key":pub_pem}
    url = "http://localhost:8000/client-login" 
    response = requests.post(url, json=payload)
    # print(response.status_code)
    encrypted_response_data = response.json()
    encrypted_data = encrypted_response_data["encrypted_data"]
    encrypted_token_aes_key = encrypted_response_data["aes_key"]
    # print(encrypted_token_aes_key)
    decrypted_token_aes_key = keys.decrypt_aes_key_with_rsa_private(encrypted_token_aes_key,priv_key)
    decrypted_data = keys.decrypt_from_url(encrypted_data,decrypted_token_aes_key)

    print(decrypted_data)
    access_token = decrypted_data['access_token']
    keys.set_token(access_token)
    keys.set_rsa_pub(pub_key)
    keys.set_rsa_private(priv_key)
    keys.set_rsa_server_public(server_public_key)
    keys.set_global_aes_key(aes_key)
    # print(payload)


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