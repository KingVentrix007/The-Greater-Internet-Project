import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# -- Load RSA Public Key --
def load_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode(), backend=default_backend())

# -- Load RSA Private Key --
def load_private_key(pem_str, password=None):
    return serialization.load_pem_private_key(pem_str.encode(), password=password, backend=default_backend())

# -- Encrypt message with Fernet AES --
def fernet_encrypt(plaintext, fernet_key):
    f = Fernet(fernet_key)
    token = f.encrypt(plaintext.encode())
    return token.decode()

# -- Decrypt message with Fernet AES --
def fernet_decrypt(token, fernet_key):
    f = Fernet(fernet_key)
    return f.decrypt(token.encode()).decode()

# -- Encrypt Fernet key with RSA public key --
def rsa_encrypt_key(fernet_key, public_key_pem):
    public_key = load_public_key(public_key_pem)
    encrypted_key = public_key.encrypt(
        fernet_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return base64.b64encode(encrypted_key).decode()

# -- Decrypt Fernet key with RSA private key --
def rsa_decrypt_key(encrypted_key_b64, private_key_pem, password=None):
    encrypted_key = base64.b64decode(encrypted_key_b64)
    private_key = load_private_key(private_key_pem, password)
    fernet_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return fernet_key

# -- Full Encrypt Function --
def encrypt_string_with_fernet_rsa(plaintext, rsa_pub_pem):
    fernet_key = Fernet.generate_key()
    encrypted_data = fernet_encrypt(plaintext, fernet_key)
    encrypted_key = rsa_encrypt_key(fernet_key, rsa_pub_pem)
    return json.dumps({
        "ciphertext": encrypted_data,
        "rsa_key": encrypted_key
    }, indent=2)

# -- Full Decrypt Function --
def decrypt_payload(json_payload, rsa_priv_pem, password=None):
    data = json.loads(json_payload)
    fernet_key = rsa_decrypt_key(data["rsa_key"], rsa_priv_pem, password)
    return fernet_decrypt(data["ciphertext"], fernet_key)


# Encrypt UUID with RSA Public Key
def encrypt_user_id(uuid_str, rsa_pub_pem):
    public_key = load_public_key(rsa_pub_pem)
    encrypted = public_key.encrypt(
        uuid_str.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

# Decrypt UUID with RSA Private Key
def decrypt_user_id(encrypted_uuid_b64, rsa_priv_pem, password=None):
    encrypted = base64.b64decode(encrypted_uuid_b64)
    private_key = load_private_key(rsa_priv_pem, password)
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()