import httpe_error
class Response:
    def __init__(self, body="", status="200 OK",status_code=200, headers=None):
        self.body = body
        # if(status ==  None):
        #     status = httpe_error.get_error_description(status_code)
        self.status = status
        self.status_code = status_code

        self.headers = headers if headers else {}

    def serialize(self):
        response_lines = [
            "RESPONSE:HTTPE/1.0",
            f"STATUS:{self.status}",
            f"STATUS_CODE:{self.status_code}",
            f"CONTENT_LENGTH:{len(self.body)}",
        ]
        for key, value in self.headers.items():
            response_lines.append(f"{key}:{value}")
        response_lines.append("END")
        response_lines.append(self.body)
        return "\n".join(response_lines)
    def error(message="Internal Server Error", status="500 INTERNAL SERVER ERROR",status_code=500):
        return Response(body=message, status=status,status_code=status_code)

