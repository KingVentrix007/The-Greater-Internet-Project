from datetime import datetime, timezone, timedelta
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json


def create_corticate(hostname="localhost",valid_time_days=100,cert_pub_key=None,private_key_path="private_key.pem",save=False,load=False) -> dict:
    if(load == True and save == True):
        return None
    if(load == True):
        with ("cert.crte","r") as f:
            cert = json.load(f)
            return cert
    private_key = load_private_key(private_key_path)
    cert_internal = {
    "hostname": hostname,
    "valid_from": datetime.now(timezone.utc).isoformat(),
    "valid_to": (datetime.now(timezone.utc) + timedelta(days=valid_time_days)).isoformat(),
    "public_key": cert_pub_key
    }
    hashed_cert = hashlib.sha256(json.dumps(cert_internal).encode("utf-8")).digest()
    signature = private_key.sign(hashed_cert,padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256())
    cert = {"cert": cert_internal,"hash":hashed_cert.hex(),"signature":signature.hex()}
    try:
        if(save == True):
            with open("cert.crte","w") as f:
                cert_plain = json.dumps(cert)
                f.write(cert_plain)
    except Exception as e:
        print("cert saving error",e)
    return cert



def load_private_key(filepath: str, password: bytes = None):
    """
    Load an RSA private key from a PEM file.
    
    :param filepath: Path to the PEM file.
    :param password: Password for encrypted key, or None if unencrypted.
    :return: Private key object.
    """
    with open(filepath, "rb") as f:
        key_data = f.read()
    return serialization.load_pem_private_key(
        key_data,
        password=password,
        backend=default_backend()
    )

def load_public_key(filepath: str):
    """
    Load an RSA public key from a PEM file.
    
    :param filepath: Path to the PEM file.
    :return: Public key object.
    """
    with open(filepath, "rb") as f:
        key_data = f.read()
    return serialization.load_pem_public_key(
        key_data,
        backend=default_backend()
    )

def create_pem_files():
    # print(__name__)
    # if __name__ != "__main__":
    #     raise RuntimeError("This function should be called manually by the user")
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # or PKCS8
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("private_key.pem", "wb") as f:
        f.write(private_pem)
    with open("public.pem", "wb") as f:
        f.write(public_pem)

def verify_cert(cert_data,hostname,public_key_path,pub_rsa_key):
    public_key = load_public_key(public_key_path)
    cert_data = json.loads(cert_data)
    certificate = cert_data['cert']
    cert_hash = cert_data['hash']
    cert_signature = cert_data["signature"]
    if(hostname != certificate['hostname']):
        print("HostNameMissMatch")
        return False
    try:
        internal_hash = hashlib.sha256(json.dumps(certificate).encode("utf-8")).digest()
        public_key.verify(bytes.fromhex(cert_signature),internal_hash,padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
    except Exception as e:
        print("Error")
        return False
    if(pub_rsa_key != certificate['public_key']):
        print("Pub key missmatch")
        return False
    return True
