from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json

# Generate RSA private key (2048 bits)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Serialize private key to PEM (no encryption for simplicity)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Convert bytes to strings for JSON
private_key_str = private_pem.decode('utf-8')
public_key_str = public_pem.decode('utf-8')

# Create a JSON-friendly dictionary
def get_public_key(string=True):
    if(string):
        return public_key_str
    else:
        return public_key
def get_private_key(string=True):
    if(string):
        return private_key_str
    else:
        return private_key