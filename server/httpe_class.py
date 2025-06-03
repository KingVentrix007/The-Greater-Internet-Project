class Response:
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
        return Response(body=message, status=status)

