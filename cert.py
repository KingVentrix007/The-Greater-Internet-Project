from datetime import datetime, timezone, timedelta
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import json


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
public_key = private_key.public_key()

cert_internal = {
    "hostname": "1245",
    "valid_from": datetime.now(timezone.utc).isoformat(),
    "valid_to": (datetime.now(timezone.utc) + timedelta(days=100)).isoformat(),
    "public_key": ""
}
hashed_cert = hashlib.sha256(json.dumps(cert_internal).encode("utf-8")).hexdigest()
sig = private_key.sign(hashed_cert.encode("utf-8"),padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256())
cert = {"cert": cert_internal,"hash":hashed_cert,"signature":sig}
# message = hashed_cert.encode("utf-8")
# signature = private_key.sign(
#     message,
#     padding.PSS(
#         mgf=padding.MGF1(hashes.SHA256()),
#         salt_length=padding.PSS.MAX_LENGTH
#     ),
#     hashes.SHA256()
# )
print(cert)