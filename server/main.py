from fastapi import FastAPI
import keys
import json
from cert  import load_pem_key, create_certificate, serialize_public_key
app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI!"}

@app.get("/httpe-init")
def httpe_init():
    # Load server private key (used for TLS-like operations)
    # privkey = load_pem_key("server_private.pem", is_private=True)

    # Load trusted root private key to sign the certificate
    root_privkey = load_pem_key("root_private.pem", is_private=True)

    # Load or regenerate server public key to embed in certificate
    pubkey = load_pem_key("server_private.pem", is_private=True).public_key()

    # Create a certificate signed by the trusted root
    current_cert = create_certificate(
        subject_name="http://127.0.0.1",
        pubkey_b64=serialize_public_key(pubkey),
        issuer="httpe auth",
        private_key=root_privkey  # signer (CA key)
    )
    return current_cert
    

