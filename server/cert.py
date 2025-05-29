from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import json
import base64
from datetime import datetime, timedelta
import hashlib
from cryptography.hazmat.backends import default_backend

# Generate root CA keypair (or load from file)
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

# Serialize public key for cert
def serialize_public_key(pubkey):
    return base64.b64encode(
        pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()

# Sign data using RSA private key
def sign_data(data: bytes, private_key) -> str:
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# Verify signature using public key
def verify_signature(data: bytes, signature_b64: str, public_key) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Verification failed:", e)
        return False

# Create a simple certificate object
def create_certificate(subject_name: str, pubkey_b64: str, issuer: str, private_key):
    cert = {
        "version": 1,
        "subject": subject_name,
        "issuer": issuer,
        "public_key": pubkey_b64,
        "usage": ["server_auth"],
        "issued": datetime.utcnow().isoformat(),
        "expires": (datetime.utcnow() + timedelta(days=365)).isoformat()
    }

    # Compute fingerprint (before signing)
    cert_data = json.dumps(cert, sort_keys=True).encode()
    # fingerprint = hashlib.sha256(cert_data).hexdigest()
    # cert["fingerprint"] = fingerprint

    # Now sign the certificate
    cert["signature"] = sign_data(cert_data, private_key)
    return cert
# Verify the certificate
def verify_certificate(cert: dict, trusted_public_key) -> bool:
    sig = cert.pop("signature")
    cert_data = json.dumps(cert, sort_keys=True).encode()
    result = verify_signature(cert_data, sig, trusted_public_key)
    cert["signature"] = sig  # Put it back
    return result



# --- DEMO ---
def save_pem_key(key, filename, is_private=False):
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filename, "wb") as f:
        f.write(pem)
def load_pem_key(filename, is_private=False):
    with open(filename, "rb") as f:
        pem_data = f.read()
    
    if is_private:
        return serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend()
        )
    else:
        return serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
def generate_cert():
    # Step 1: Generate root key (this would be your trusted CA)
    root_private, root_public = generate_key_pair()

    # Step 2: Generate key for the server/client
    server_private, server_public = generate_key_pair()

    # Step 3: Create certificate signed by the root
    server_cert = create_certificate(
        subject_name="myserver.local",
        pubkey_b64=serialize_public_key(server_public),
        issuer="My Custom CA",
        private_key=root_private
    )

    # Save the certificate to a file
    with open("server_cert.json", "w") as f:
        json.dump(server_cert, f, indent=2)

    # Save the trusted root public key to a file (this is pinned)
    save_pem_key(root_public, "trusted_root_pub.pem")

    # Optionally save private keys (for testing or server use)
    save_pem_key(root_private, "root_private.pem", is_private=True)
    save_pem_key(server_private, "server_private.pem", is_private=True)

    print("✅ Certificate and keys written to files.")
    print("  - server_cert.json")
    print("  - trusted_root_pub.pem")
    print("  - root_private.pem (optional)")
    print("  - server_private.pem (optional)")
# print("Certificate valid:", valid)
# generate_cert()