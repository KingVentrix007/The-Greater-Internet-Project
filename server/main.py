from fastapi import FastAPI
import keys
app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello, FastAPI!"}

@app.get("/httpe-init")
def httpe_init():
    # Returns server RSA public key and certificate
    pass