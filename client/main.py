import handle_cert
import keys
import base64


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
    
    # Serialize keys (for storage, transmission, etc)
    # priv_pem = keys.serialize_private_key(priv_key)

    pub_pem = keys.serialize_public_key(pub_key)
    encrypted_aes_key = keys.encrypt_aes_key_with_rsa_public(aes_key, server_public_key)
    username = "tristan"
    password = "tristan"
    username_enc = keys.encrypt_string_with_aes(aes_key,username)
    password_enc = keys.encrypt_string_with_aes(aes_key,password)
    payload = {"username":username_enc,"password":password_enc,"aes_key":encrypted_aes_key,"rsa_key":pub_pem}

init_connection()