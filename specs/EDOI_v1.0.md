# Encrypted Data Over Internet (EDOI) Protocol

## Version: 1.0

### Status: Draft

### Author: Tristan Kuhn

### Date: 2025-06-06

---

## 1. Introduction

The Encrypted Data Over Internet (EDOI) protocol is a transport-layer encryption specification designed to operate beneath HTTPE. It is engineered to provide strong data confidentiality, including obfuscation of metadata. EDOI employs ephemeral AES-256 session keys negotiated through a secure RSA-based handshake. This document defines version 1.0 of the protocol.

> **Note:** EDOI guarantees data confidentiality, but does **not** inherently guarantee server authenticity.

---

## 2. Protocol Overview

EDOI provides end-to-end encryption with per-session keys, minimizing exposure in the event of compromise. It utilizes a hybrid encryption model:

* **Asymmetric encryption** (RSA-2048) is used during the initial key exchange.
* **Symmetric encryption** (AES-256) is used for all subsequent communications.

Metadata exposure is strictly limited to the protocol version and request type, both of which may be encrypted in future versions.

---

## 3. Handshake Protocol

The handshake initializes secure communication by negotiating a shared AES-256 session key.

### 3.1 Client Requests RSA Key

* **Request Type:** `GET_RSA`
* **Action:** The client requests the server’s RSA public key.

### 3.2 Client Shares AES Key

* **Request Type:** `SHARE_AES`
* **Action:**

  * Client generates a 256-bit AES key.
  * Client generates a UUIDv4 identifier (`client_id`).
  * Both values are encrypted using the server’s RSA public key.
  * The encrypted payload is sent to the server.

### 3.3 Server Processes Payload

* Server decrypts the AES key and `client_id`.
* Associates the AES key with the `client_id`.
* Logs the `client_id`.
* Generates a **session token**, encrypted with the server’s internal **master AES key**.
* Sends the token and a server **certificate** to the client.

### 3.4 Client Verifies Certificate

* Verification is done using an **out-of-band pre-shared key**.

### 3.5 Encrypted Communication Commences

* **Request Type:** `REQ_ENC`
* All further communication is encrypted using the AES session key.

### 3.6 Token Expiry

* Upon token expiration, the full handshake (steps 3.1–3.5) must be repeated.

---

## 4. Protocol Constraints

### 4.1 Security Rules

* Server restart **rotates** the master AES key, invalidating all tokens.
* **UUIDs (`client_id`) must be logged** for session correlation and auditing.
* **Token lifespan** must not exceed **24 hours**.
* **Packet expiration:** Any encrypted request must expire within **2 minutes** of its timestamp.
* **Protocol downgrade attacks** are mitigated by disallowing communication with earlier protocol versions.

### 4.2 Metadata Exposure

Only the following fields are visible:

* Protocol version: `HTTPE/{version}`
* Request type: (`GET_RSA`, `SHARE_AES`, `REQ_ENC`)

Future versions may obfuscate or encrypt these fields as well.

---

## 5. Cryptographic Standards

| Component         | Algorithm / Standard          |
| ----------------- | ----------------------------- |
| Asymmetric Crypto | RSA, 2048-bit                 |
| Symmetric Crypto  | AES, 256-bit |
| UUIDs             | UUIDv4                        |
| Token Encryption  | AES-256 (Server's master key) |

---

## 6. Future Considerations

* Certificate trust may be augmented with formal PKI in future versions.
* Encrypted metadata fields and additional request types are planned.
* Multi-session AES rotation and perfect forward secrecy are under review.

---

## 7. Implementation Notes

* Implementations **must** reject expired tokens and packets.
* Implementations **must not** allow fallback to deprecated versions.
* Certificate verification must rely on a **secure out-of-band** shared secret.

---

## 8. Security Disclaimer

EDOI is designed to protect the **confidentiality** of transmitted data. It does not validate the **identity** of the server without external mechanisms. Implementers must ensure proper verification methods are employed in production environments.

---

## 9. Change Log

**v1.0 – 2025-06-06**

* Initial specification draft finalized.

---

End of Specification
