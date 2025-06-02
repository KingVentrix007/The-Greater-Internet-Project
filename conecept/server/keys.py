from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
import json
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import HTTPException, status
from cryptography.fernet import Fernet
import urllib.parse
import os
#globals


SECRET_KEY = "ThisSecretKey" # Change to correct value during prod
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

client_rsa_keys = {}
client_aes_keys = {}
# Generate the private key (2048-bit)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize the private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),  # Or use BestAvailableEncryption(b"password")
)

# Generate and serialize the public key
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


def set_client_key(client_id,key):
    global client_aes_keys
    client_aes_keys[client_id] = key
def get_client_key(client_id):
    global client_aes_keys
    return client_aes_keys.get(client_id,None)

def get_public_pem():
    return public_pem
def get_private_pem():
    return private_pem


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


def decrypt_string_with_aes(aes_key: bytes, encrypted_b64: str) -> str:
    aesgcm = AESGCM(aes_key)
    encrypted_package = base64.b64decode(encrypted_b64.encode('utf-8'))
    nonce = encrypted_package[:12]
    ciphertext = encrypted_package[12:]
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_bytes.decode('utf-8')

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


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

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

def load_public_key(pem_str):
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))

def encrypt_string_with_aes(aes_key: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce, recommended for GCM
    plaintext_bytes = plaintext.encode('utf-8')
    encrypted = aesgcm.encrypt(nonce, plaintext_bytes, None)
    # Return nonce + encrypted ciphertext as base64 for JSON
    encrypted_package = nonce + encrypted
    return base64.b64encode(encrypted_package).decode('utf-8')
