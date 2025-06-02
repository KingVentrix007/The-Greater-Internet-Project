import json
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import requests
import base64
def load_trusted_root_pubkey(path="trusted_root_pub.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_certificate(cert: dict, trusted_pubkey):
    # Extract and remove signature
    signature = base64.b64decode(cert["signature"])
    cert_copy = cert.copy()
    del cert_copy["signature"]

    # Recompute the fingerprint
    cert_data = json.dumps(cert_copy, sort_keys=True).encode()
    # fingerprint_check = hashes.Hash(hashes.SHA256())
    # fingerprint_check.update(cert_data)
    # computed_fingerprint = fingerprint_check.finalize().hex()

    # if cert.get("fingerprint") != computed_fingerprint:
    #     print("❌ Fingerprint mismatch!")
    #     return False

    # Verify digital signature
    try:
        trusted_pubkey.verify(
            signature,
            cert_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except InvalidSignature:
        print("❌ Signature verification failed!")
        return False

    # Check date validity
    now = datetime.utcnow()
    issued = datetime.fromisoformat(cert["issued"])
    expires = datetime.fromisoformat(cert["expires"])
    if not (issued <= now <= expires):
        print("❌ Certificate is expired or not yet valid!")
        return False

    # Optional: check usage
    if "usage" in cert and "server_auth" not in cert["usage"]:
        print("❌ Usage field is invalid!")
        return False

    print("✅ Certificate is valid.")
    return True
def request_certificate(server_url="http://127.0.0.1:8000/httpe-init"):
    try:
        response = requests.get(server_url)
        response.raise_for_status()
        cert = response.json()
        print("Received Certificate:")
        print(cert)
        return cert
    except requests.exceptions.RequestException as e:
        print(f"Error requesting certificate: {e}")
        return None