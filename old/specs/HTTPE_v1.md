# HyperText Transfer Encrypted Protocol (HTTPE)

## Version: 1.0

### Status: Draft

### Author: Tristan Kuhn


### Date: 2025-06-06

---

## 1. Introduction

The HyperText Transfer Encrypted Protocol (HTTPE) defines a secure, metadata-restricted request format designed to operate in conjunction with the EDOI encryption layer. HTTPE supports specialized request types necessary for encrypted key exchanges and secure data transport.

This document outlines the structure, behavior, and security validations for HTTPE version 1.0.

---

## 2. Request Format

HTTPE requests follow a strict header-based format, optionally followed by a body (for `POST` operations):

```
VERSION: HTTPE/1.0
METHOD: GET | POST
TYPE: GET_RSA | SHARE_AES | REQ_ENC
ID: <RSA-encrypted UUID> (optional, required for SHARE_AES)
TOKEN: <AES-encrypted token> (required for REQ_ENC)
LOCATION: /path/to/resource
HEADERS:
is_com_setup: true | false
client_id: <UUID or None>
packet_id: <UUIDv4>
timestamp: <ISO 8601 e.g., 2025-06-06T12:34:56Z>
compressions: true | false (optional, not implemented)
END
[POST BODY – assumed JSON unless otherwise specified]
```

---

## 3. Request Types

HTTPE supports three primary request types:

### 3.1 `GET_RSA`

* **Purpose:** Request the server’s RSA public key.
* **Function:** Initializes server-side RSA key distribution.
* **Notes:**

  * No access to protected endpoints.
  * Internally handled as a `POST`.

### 3.2 `SHARE_AES`

* **Purpose:** Send AES session key and UUID.
* **Function:** Triggers AES session key registration and token generation.
* **Notes:**

  * Requires `ID` (RSA-encrypted UUID).
  * No endpoint access.
  * Internally treated as a `POST`.

### 3.3 `REQ_ENC`

* **Purpose:** Secure request transmission after handshake.
* **Function:** All headers and body are AES-encrypted.
* **Notes:**

  * Requires a valid `TOKEN`.
  * Only `VERSION` and `TYPE` remain visible.
  * Server responds with AES-encrypted data.

### 3.4 `REQ_END`

* **Purpose:** (Reserved) Session termination (future use).

---

## 4. Connection Validation

Servers must reject incoming connections under any of the following conditions:

* `packet_id` is missing or has already been used (anti-replay enforcement)
* `timestamp` is missing or exceeds a 2-minute freshness window
* `client_id` is unknown or mismatched with token contents
* Token reuse across sessions or tampered token detected
* Token’s embedded ID does not match the request’s `client_id`

> Any mismatch or suspicious behavior mandates logging, session termination, and full handshake renewal.

---

## 5. Security Constraints

* **Replay Protection:** Enforced via `packet_id` and timestamp freshness.
* **Downgrade Attacks:** Protocol version fallback is strictly forbidden.
* **Token Confidentiality:** Server-issued tokens are encrypted using an internal master AES key.
* **Request Confidentiality:** Enforced via AES-256 session key.
* **Compression Layer:** Any compression must be applied **before** encryption (not yet implemented).

---

## 6. Internal Behavior

| Request Type | Internally Treated As | Encrypted?        | Notes                                   |
| ------------ | --------------------- | ----------------- | --------------------------------------- |
| `GET_RSA`    | POST                  | No                | Only metadata shared                    |
| `SHARE_AES`  | POST                  | Partial (payload) | AES key and ID encrypted with RSA       |
| `REQ_ENC`    | POST or GET           | Yes               | Headers/body encrypted with AES session |
| `REQ_END`    | N/A                   | Reserved          | Session teardown (future feature)       |

---

## 7. Summary

HTTPE provides the transport scaffolding necessary to enable the secure and flexible use of the EDOI encryption protocol. By standardizing secure metadata handling, request structuring, and validation mechanisms, HTTPE ensures confidentiality and integrity while maintaining extensibility for future features like compression and session management.

---

## 8. Change Log

**v1.0 – 2025-06-06**

* Initial specification drafted.

---

End of Specification
