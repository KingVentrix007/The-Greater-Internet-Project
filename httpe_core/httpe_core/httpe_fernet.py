import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
class HttpeFernet():
    IV_LEN = 12   
    TAG_LEN = 16
    def __init__(self, key: bytes = None):
        if key is None:
            key = os.urandom(32)  # 256-bit key
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256")
        self._key = key

    def get_key(self,raw=True) -> bytes:
        if(raw == True):
            return self._key


    def encrypt(self, data: bytes) -> str:
        iv = os.urandom(self.IV_LEN)
        encryptor = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        ciphertext = encryptor.update(data) + encryptor.finalize()
        token = iv + encryptor.tag + ciphertext
        return base64.urlsafe_b64encode(token).decode()

    def decrypt(self, token: str) -> bytes:
        raw = base64.urlsafe_b64decode(token.encode())
        iv = raw[:self.IV_LEN]
        tag = raw[self.IV_LEN:self.IV_LEN + self.TAG_LEN]
        ciphertext = raw[self.IV_LEN + self.TAG_LEN:]

        decryptor = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()