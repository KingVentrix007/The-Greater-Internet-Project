import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives import keywrap
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
import urllib.parse

global_token = None

global_rsa_pub = None
global_rsa_private = None

global_rsa_server_pub = None

global_aes_key = None

def set_global_aes_key(key):
    global global_aes_key
    global_aes_key = key
def get_global_aes_key():
    global global_aes_key
    return global_aes_key

def set_rsa_pub(key):
    global global_rsa_pub
    global_rsa_pub = key
def set_rsa_private(key):
    global global_rsa_private
    global_rsa_private = key
def get_rsa_public():
    global global_rsa_pub
    return global_rsa_pub
def get_rsa_private():
    global global_rsa_private
    return global_rsa_private
def set_rsa_server_public(key):
    global global_rsa_server_pub
    global_rsa_server_pub = key
def get_rsa_server_public():
    global global_rsa_server_pub
    return global_rsa_server_pub
def set_token(token):
    global global_token
    global_token = token
def get_token():
    global global_token
    return global_token

# Generate RSA key pair
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize RSA keys to PEM format strings for storage or transmission
def serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')

def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

# Load keys back from PEM strings
def load_private_key(pem_str):
    return serialization.load_pem_private_key(pem_str.encode('utf-8'), password=None)

def load_public_key_str(pem_str):
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))
def load_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str)

# Generate a random AES key (256-bit)
def generate_aes_key():
    return os.urandom(32)  # 32 bytes = 256 bits

# Encrypt AES key with RSA public key
def encrypt_aes_key_with_rsa_public(aes_key, public_key):
    encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # base64 encode for JSON safety
    return base64.b64encode(encrypted).decode('utf-8')

# Decrypt AES key with RSA private key
def decrypt_aes_key_with_rsa_private(encrypted_aes_key_b64, private_key):
    encrypted = base64.b64decode(encrypted_aes_key_b64.encode('utf-8'))
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted


def encrypt_string_with_aes(aes_key: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce, recommended for GCM
    plaintext_bytes = plaintext.encode('utf-8')
    encrypted = aesgcm.encrypt(nonce, plaintext_bytes, None)
    # Return nonce + encrypted ciphertext as base64 for JSON
    encrypted_package = nonce + encrypted
    return base64.b64encode(encrypted_package).decode('utf-8')

# Decrypt the base64 encoded encrypted string using AES-GCM
def decrypt_string_with_aes(aes_key: bytes, encrypted_b64: str) -> str:
    aesgcm = AESGCM(aes_key)
    encrypted_package = base64.b64decode(encrypted_b64.encode('utf-8'))
    nonce = encrypted_package[:12]
    ciphertext = encrypted_package[12:]
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_bytes.decode('utf-8')

def encrypt_for_url(data: any,key) -> str:
    if data is None:
        return None
    # Ensure JSON is serialized to a string
    json_data = json.dumps(data)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(json_data.encode())  # Encrypted bytes
    url_safe = urllib.parse.quote(encrypted.decode())  # Make it URL-safe
    return url_safe

def decrypt_from_url(url_safe: str,key) -> str:
    cipher = Fernet(key)
    encrypted = urllib.parse.unquote(url_safe).encode()
    decrypted = cipher.decrypt(encrypted).decode()
    data_out = json.loads(decrypted)
    return data_out
