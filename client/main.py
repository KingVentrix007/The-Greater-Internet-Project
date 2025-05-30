import json
import handle_cert
import keys
import base64
import requests
from datetime import datetime, timezone, timedelta
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

import os
import time
def send_request_post(request,path):
    url = f"http://localhost:8000/{path}" 
    enc_request = keys.encrypt_for_url(request,base64.b64encode((keys.get_global_aes_key())))
    package_verify_data = {"time_sent":datetime.now(timezone.utc).isoformat(),"package_code": base64.b64encode(os.urandom(128)).decode("utf-8")}
    # time.sleep(125)
    package_verify_data_enc  =keys.encrypt_for_url(package_verify_data,base64.b64encode((keys.get_global_aes_key())))
    payload = {"request_data":enc_request,"package_verify":package_verify_data_enc}
    headers = {"Authorization": f"Bearer {keys.get_token()}"}
    response = requests.post(url, json=payload,headers=headers)
    try:
        encrypted_response_data = response.json()
        enc_data = encrypted_response_data["enc_data"]
        enc_time_send = encrypted_response_data["time_send"]
        time_iso_send = keys.decrypt_string_with_aes((keys.get_global_aes_key()), enc_time_send)
        sent_time = datetime.fromisoformat(time_iso_send)
        now = datetime.now(timezone.utc)
        if now - sent_time > timedelta(minutes=2):
            return None
        return_data = keys.decrypt_from_url(enc_data, base64.b64encode(keys.get_global_aes_key()))

        # Replace response content with decrypted data JSON
        decrypted_json_str = json.dumps(return_data)

        # response._content expects bytes
        response._content = decrypted_json_str.encode('utf-8')

        # Also update Content-Length header accordingly
        response.headers['Content-Length'] = str(len(response._content))
        print("My res")
        return response

    except Exception as e:
        print(e)
        return response


def test_req():
    payload = {"username":"tristan"}
    res = send_request_post(payload,"test")
    print(res.status_code)
    print(res.json())


init_connection()
test_req()