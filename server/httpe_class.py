class _Response:
    def __init__(self, body="", status="200 OK", headers=None):
        self.body = body
        self.status = status
        self.headers = headers if headers else {}

    def serialize(self):
        response_lines = [
            "RESPONSE:HTTPE/1.0",
            f"STATUS:{self.status}",
            f"CONTENT_LENGTH:{len(self.body)}",
        ]
        for key, value in self.headers.items():
            response_lines.append(f"{key}:{value}")
        response_lines.append("END")
        response_lines.append(self.body)
        return "\n".join(response_lines)
    def error(message="Internal Server Error", status="500 INTERNAL SERVER ERROR"):
        return _Response(body=message, status=status)

import json

class HttpeResponse:
    def __init__(self, raw_response: str):
        self.raw_response = raw_response.strip()
        self.headers = {}
        self._body_str = ""

        self._parse()

    def _parse(self):
        header_section, body_section = self.raw_response.split("END", 1)
        header_lines = header_section.strip().splitlines()
        self._body_str = body_section.strip()

        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                self.headers[key.strip()] = value.strip()

        self.status = self.headers.get("STATUS")
        self.content_length = int(self.headers.get("CONTENT_LENGTH", -1))

    def body(self) -> str:
        return self._body_str

    def json(self) -> dict:
        try:
            return json.loads(self._body_str)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in response body: {e}")

    def __repr__(self):
        return f"<HttpeResponse status={self.status} content_length={self.content_length}>"

