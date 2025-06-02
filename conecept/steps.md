# HTTPE Protocol Steps

## 1. Key Exchange Phase (Initial Contact)

- **Client → Server:**  
  Request server's RSA public key and certificate (e.g., `GET /httpe-init`).

- **Server → Client:**  
  Sends RSA public key and custom certificate.

---

## 2. Client Authentication Phase

- **Client:**  
  - Generates temporary RSA key pair.  
  - Generates random AES key.  
  - Encrypts username+password with AES key.  
  - Encrypts AES key with server's RSA public key.  
  - Sends encrypted encrypted AES key, and client's RSA public key.

- **Client → Server:**  
  Sends the above data.

---

## 3. Server Validates and Issues Session

- **Server:**  
  - Decrypts AES key (using server RSA private key).  
  - Decrypts username+password (using AES key).  
  - Validates credentials.  
  - If valid, creates:  
    - Session token (random value).  
    - New AES key for session.  
  - Stores token ↔ AES key ↔ client RSA public key mapping (10 min expiry).  
  - Encrypts token with new AES key.  
  - Encrypts AES key with client's RSA public key.

- **Server → Client:**  
  Sends encrypted token and encrypted AES key.

---

## 4. Client Confirms Session

- **Client:**  
  - Decrypts AES key and token.  
  - Re-encrypts token with server's AES key.  
  - Generates new RSA key pair.  
  - Sends re-encrypted token and new RSA public key.

- **Client → Server:**  
  Sends the above data.

---

## 5. Server Confirms Final Setup

- **Server:**  
  - Verifies token.  
  - Rotates AES key.  
  - Updates token ↔ AES key ↔ client RSA public key mapping.  
  - Encrypts new AES key with client's new RSA public key.

- **Server → Client:**  
  Sends encrypted new AES key.

---

## 6. Data Exchange Phase

- All subsequent communication for the session (up to 30 minutes):  
  - Client sends requests encrypted with session AES key, including the encrypted token.  
  - Server verifies token and decrypts request.  
  - Server responds with AES-encrypted data.

