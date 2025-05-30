from fastapi import FastAPI,Depends,status,HTTPException,Response,Request
import keys
import json
from cert  import load_pem_key, create_certificate, serialize_public_key
from pydantic import BaseModel
import user
from cryptography.fernet import Fernet
from fastapi.responses import JSONResponse
from jose import JWTError
import jwt
from starlette.types import Receive, Scope, Send
import base64
import time
from datetime import datetime, timedelta,timezone
app = FastAPI()
from starlette.responses import StreamingResponse

from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class LoginPayload(BaseModel):
    username: str
    password: str
    aes_key: str
    rsa_key: str
    # packet_time:str
async def get_current_user(token: str = Depends(oauth2_scheme), db: user.AsyncSession = Depends(user.get_token_db)):
    payload = keys.decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    current_user = await user.get_user_by_username(db, username)
    if current_user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return current_user
@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI!"}

@app.get("/httpe-init")
def httpe_init():
    # Load server private key (used for TLS-like operations)
    # privkey = load_pem_key("server_private.pem", is_private=True)

    # Load trusted root private key to sign the certificate
    root_privkey = load_pem_key("root_private.pem", is_private=True)

    # Load or regenerate server public key to embed in certificate
    pubkey = load_pem_key("server_private.pem", is_private=True).public_key()

    # Create a certificate signed by the trusted root
    current_cert = create_certificate(
        subject_name="http://127.0.0.1",
        pubkey_b64=serialize_public_key(pubkey),
        issuer="httpe auth",
        private_key=root_privkey  # signer (CA key)
    )
    return current_cert

async def get_current_user_manual(request: Request) -> user.User:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    try:
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            raise ValueError()
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    payload = keys.decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")

    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    db = await user.get_token_db_dependency()  # you define this helper
    current_user = await user.get_user_by_username(db, username)
    if current_user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return current_user
@app.post("/client-login")
async def client_login(payload: LoginPayload,db: user.AsyncSession = Depends(user.get_token_db)):
    # Access data like:
    username_enc = payload.username
    password_enc = payload.password
    encrypted_aes_key = payload.aes_key
    pub_pem = payload.rsa_key
    decrypted_aes_key = keys.decrypt_aes_key_with_rsa_private(encrypted_aes_key,load_pem_key("server_private.pem", is_private=True))
    username = keys.decrypt_string_with_aes(decrypted_aes_key,username_enc)
    password = keys.decrypt_string_with_aes(decrypted_aes_key,password_enc)
    current_user = await user.authenticate_user(db, username, password)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    keys.set_client_key(current_user.id,decrypted_aes_key)
    access_token = keys.create_access_token(data={"sub": username})
    aes_token_encrypt_key = Fernet.generate_key()
    print(pub_pem)
    encrypted_aes_token_encrypt_key = keys.encrypt_aes_key_with_rsa_public(aes_token_encrypt_key,keys.load_public_key(pub_pem))
    token_data = {"access_token": access_token, "token_type": "bearer"}
    
    encrypted_token_data = keys.encrypt_for_url(token_data,aes_token_encrypt_key)
    return_data = {"encrypted_data":encrypted_token_data,"aes_key":encrypted_aes_token_encrypt_key}
    return Response(
    content=json.dumps(return_data).encode("utf-8"),
    media_type="application/octet-stream"
        )    # print(f"{username} {password}")
    # Now add server validation from database

class TestItem(BaseModel):
    username: str
@app.post("/test")
def test(item: TestItem, request: Request):
    # body = await request.body()
    # print("Raw body received by endpoint:", body.decode())
    # print(item.username)
    return {"username": "My name is"}


async def handle_return(user, response) -> Response:
    print("Hello world")
    # try:
    #     # Try to read the full body asynchronously
    #     body_bytes = await response.body()
    # except AttributeError:
    #     # If response.body() is not a coroutine, try response.body directly
    #     try:
    #         body_bytes = response.body
    #     except Exception as e:
    #         print("Could not get response body:", e)
    #         return response
    
    # # Decode bytes if needed
    # if isinstance(body_bytes, bytes):
    #     body_str = body_bytes.decode()
    # else:
    #     body_str = body_bytes

    # try:
    #     print(json.loads(body_str))
    # except Exception as e:
    #     print("Could not parse JSON response:", e)
    if isinstance(response, type(response)):
        steamed_res:StreamingResponse = response
        body = b""
        async for chunk in steamed_res.body_iterator:
            body += chunk

        print("Raw body bytes:", body)
        try:
            json_body = json.loads(body.decode())
            enc_data = keys.encrypt_for_url(json_body,base64.b64encode(keys.get_client_key(user.id)))
            # 
            
            ret_data = {"enc_data":enc_data,"time_send":keys.encrypt_string_with_aes(keys.get_client_key(user.id),datetime.now(timezone.utc).isoformat())}
            body = json.dumps(ret_data).encode("utf-8")
            print("Parsed JSON:", json_body)
        except Exception as e:
            print("Not JSON or decoding failed:", e)
            # print("Ths")
        return Response(content=body, media_type="application/json")
    else:
        print(type(response))
    return response

@app.middleware("http")
async def jwt_auth_middleware(request: Request, call_next):
    if request.url.path in ["/httpe-init", "/client-login"]:
        return await call_next(request)
    
    # Read body once
    body_bytes = await request.receive()
    print(body_bytes)
    # Try to parse as JSON to check for encryption
    try:
        body_json = json.loads(body_bytes['body'])
        print(body_json)
        # body = 
        is_enc = body_json.get("request_data",None)
        if(is_enc != None):
            is_enc = True
    except json.JSONDecodeError:
        is_enc = False
        body_json = {}

    # Handle Authorization
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return JSONResponse(status_code=401, content={"detail": "Authorization header missing"})

    try:
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            raise ValueError()
    except ValueError:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization header format"})

    try:
        current_user = await get_current_user_manual(request)
        payload = keys.decode_access_token(token)
    except JWTError:
        return JSONResponse(status_code=401, content={"detail": "Invalid token"})

    # Decrypt and patch request if encrypted
    print(is_enc)
    if is_enc:
        try:
            print("Hello")
            user_id = current_user.id
            encrypted_data = body_json["request_data"]
            decrypted = keys.decrypt_from_url(
                encrypted_data, base64.b64encode(keys.get_client_key(user_id))
            )

            if isinstance(decrypted, dict):
                new_body = json.dumps(decrypted).encode("utf-8")
            elif isinstance(decrypted, str):
                new_body = decrypted.encode("utf-8")
            else:
                new_body = decrypted

            # Patch request body by replacing scope['body'] stream
            async def receive() -> dict:
                rec_data = body_bytes
                rec_data['body'] = new_body
                return rec_data
            print("NEw: ",new_body)
            # Create a new request object with the patched body
            # modified_request = StarletteRequest(request.scope, receive)
            request._receive = receive  # patch it back for safety
            response = await call_next(request)
    


            return await handle_return(current_user, response)
        except Exception as e:
            return JSONResponse(status_code=450, content={"detail": f"Decryption failed: {str(e)}"})

    # If not encrypted, restore body for next layers
    async def receive_plain():
        return {"type": "http.request", "body": body_bytes, "more_body": False}
    
    request._receive = receive_plain  # patch it back for safety
    
    # response = await call_next(request)

    # # Buffer the response body (must fully consume body_iterator)
    response = await call_next(request)
    


    # Intercept response
    response_body = b""
    async for chunk in response.body_iterator:
        response_body += chunk

    # Modify response
    try:
        data = json.loads(response_body)
    except Exception:
        data = response_body.decode(errors="ignore")

    modified = {
        "modified": True,
        "original": data
    }

    return Response(
        content=json.dumps(modified),
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type="application/json"
    )
    # return handle_return(current_user, new_response)