# 📘 Error Code Reference for HTTPEs

## ✅ 1xx - Informational Responses

| Code | Name                    | Description                                  |
|------|-------------------------|----------------------------------------------|
| 100  | Continue                | Request received, continue sending.          |
| 101  | Switching Protocols     | Switching to a different protocol.           |
| 102  | Processing              | Server is processing, no response yet.       |

## 🔄 2xx - Success

| Code | Name                    | Description                                  |
|------|-------------------------|----------------------------------------------|
| 200  | OK                      | Standard successful response.                |
| 201  | Created                 | Resource created successfully.               |
| 202  | Accepted                | Request accepted but not yet processed.      |
| 204  | No Content              | Success, but no content to return.           |

## ⚠️ 3xx - Redirection

| Code | Name                    | Description                                  |
|------|-------------------------|----------------------------------------------|
| 301  | Moved Permanently       | Resource has a new permanent URI.            |
| 302  | Found                   | Temporary redirection.                       |
| 303  | See Other               | Response at a different URI.                 |
| 304  | Not Modified            | Cached content still valid.                  |
| 307  | Temporary Redirect      | Temporary redirect, method must not change.  |
| 308  | Permanent Redirect      | Permanent redirect, method must not change.  |

## ❌ 4xx - Client Errors

| Code | Name                    | Description                                  |
|------|-------------------------|----------------------------------------------|
| 400  | Bad Request             | Request was malformed or invalid.            |
| 401  | Unauthorized            | Authentication required.                     |
| 403  | Forbidden               | Authenticated but not allowed.               |
| 404  | Not Found               | Resource not found.                          |
| 405  | Method Not Allowed      | Method not allowed for this resource.        |
| 408  | Request Timeout         | Client took too long to send request.        |
| 409  | Conflict                | Conflict in resource state.                  |
| 410  | Gone                    | Resource permanently removed.                |
| 413  | Payload Too Large       | Request body too big.                        |
| 414  | URI Too Long            | Request URI too long.                        |
| 415  | Unsupported Media Type  | Unsupported content type.                    |
| 418  | I'm a Teapot ☕         | Joke code, useful for testing.               |
| 429  | Too Many Requests       | Rate limit exceeded.                         |

## 🛑 5xx - Server Errors

| Code | Name                    | Description                                  |
|------|-------------------------|----------------------------------------------|
| 500  | Internal Server Error   | Generic server-side error.                   |
| 501  | Not Implemented         | Functionality not supported.                 |
| 502  | Bad Gateway             | Invalid response from upstream server.       |
| 503  | Service Unavailable     | Server temporarily overloaded or down.       |
| 504  | Gateway Timeout         | Timeout while acting as proxy/gateway.       |
| 505  | Version Not Supported   | Protocol version not supported.              |
| 507  | Insufficient Storage    | Server out of storage capacity.              |

## 🔐 6xx - Secure Protocol Specific Errors (Custom)

| Code | Name                    | Description                                  |
|------|-------------------------|----------------------------------------------|
| 600  | TLS Handshake Failed    | TLS/SSL handshake could not be completed.    |
| 601  | Certificate Invalid     | Server or client certificate is invalid.     |
| 602  | Certificate Expired     | SSL certificate is expired.                  |
| 603  | Certificate Revoked     | Certificate was revoked.                     |
| 604  | Insecure Cipher Suite   | Rejected due to weak or disabled cipher.     |
| 605  | No Shared Cipher        | No compatible cipher between peers.          |
| 606  | Secure Channel Required | Unsecured request to a secure-only endpoint. |
| 607  | Token Expired           | Authentication token expired.                |
| 608  | Token Invalid           | Token failed verification.                   |
| 609  | HSTS Enforcement        | Strict HTTPS policy rejected the request.    |

## 🧪 9xx - Debug/Experimental (Optional)

| Code | Name                    | Description                                  |
|------|-------------------------|----------------------------------------------|
| 900  | Debug Mode Enabled      | Server running in debug mode.                |
| 901  | Testing Response        | Non-standard test result.                    |
| 902  | Protocol Extension Used | Custom protocol extension was invoked.       |
