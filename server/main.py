from fastapi import FastAPI,Depends,status,HTTPException,Response,Request
import httpe_server
app = FastAPI()


@app.post("/fun-fact")
def fun_fact():
    return {"fact":"The world is round"}

@app.get("/httpe-init")
def init_connection():
    return httpe_server.httpe_init()

@app.post("/client-login")
def login(payload):
    return httpe_server.client_login(payload)


@app.middleware("http")
def middle(request,call_next):
    return httpe_server.jwt_auth_middleware(request,call_next)