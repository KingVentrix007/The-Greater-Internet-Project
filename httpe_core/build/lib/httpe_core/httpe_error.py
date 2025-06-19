def get_error_description(code: int) -> str:
    error_map = {
        # 1xx - Informational
        100: "Continue",
        101: "Switching Protocols",
        102: "Processing",

        # 2xx - Success
        200: "OK",
        201: "Created",
        202: "Accepted",
        204: "No Content",

        # 3xx - Redirection
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        304: "Not Modified",
        307: "Temporary Redirect",
        308: "Permanent Redirect",

        # 4xx - Client Errors
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        408: "Request Timeout",
        409: "Conflict",
        410: "Gone",
        413: "Payload Too Large",
        414: "URI Too Long",
        415: "Unsupported Media Type",
        418: "I'm a Teapot ☕",
        429: "Too Many Requests",

        # 5xx - Server Errors
        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
        505: "Version Not Supported",
        507: "Insufficient Storage",

        # 6xx - Secure Protocol Specific Errors
        600: "TLS Handshake Failed",
        601: "Certificate Invalid",
        602: "Certificate Expired",
        603: "Certificate Revoked",
        604: "Insecure Cipher Suite",
        605: "No Shared Cipher",
        606: "Secure Channel Required",
        607: "Token Expired",
        608: "Token Invalid",
        609: "HSTS Enforcement",

        # 9xx - Debug/Experimental
        900: "Debug Mode Enabled",
        901: "Testing Response",
        902: "Protocol Extension Used",
    }

    description = error_map.get(code)
    if description:
        return f"{code} {description.upper()}"
    else:
        return f"{code} UNKNOWN ERROR CODE"

class PrivateKeyExpiredError(Exception):
    """Raised when a private key has expired."""
    pass

class PublicKeyExpiredError(Exception):
    """Raised when a private key has expired."""
    pass