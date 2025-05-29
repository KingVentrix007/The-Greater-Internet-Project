from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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