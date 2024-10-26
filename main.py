from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from fastapi.responses import HTMLResponse
from keycloak import KeycloakAdmin, KeycloakOpenID
from fastapi.security import OAuth2AuthorizationCodeBearer
import requests
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import JWTError
import jwt
from schemas import Register, UserSignInRequest, Shoe, ShoeCreate
from fastapi.middleware.cors import CORSMiddleware

import models
import schemas
from database import SessionLocal, engine
from crud import create_shoe, get_shoes, get_shoe, update_shoe_stock, delete_shoe


models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],  
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"],
)

KEYCLOAK_SERVER_URL = "https://vinyu.lat/"
REALM_NAME = "api"
CLIENT_ID = "clientest"
CLIENT_SECRET = "DS3KXCjxJDxSisseYMB4f0vgHG27l2ml"

keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    client_id=CLIENT_ID,
    realm_name=REALM_NAME,
    client_secret_key=CLIENT_SECRET
)


oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/auth",
    tokenUrl=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/protocol/openid-connect/token"
)

keycloak_admin = KeycloakAdmin( 
    server_url=KEYCLOAK_SERVER_URL, 
    username='marvnramos', 
    password='123', 
    realm_name="master", 
    client_id='admin-cli', 
    verify=True 
) 

def get_keycloak_public_key():
    """Retrieve the public key from Keycloak's OpenID configuration"""
    openid_config_url = f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}/.well-known/openid-configuration"
    response = requests.get(openid_config_url)

    if response.status_code == 200:
        jwks_uri = response.json()["jwks_uri"]
        jwks_response = requests.get(jwks_uri)
        if jwks_response.status_code == 200:
            jwks = jwks_response.json()
            cert_b64 = jwks['keys'][0]['x5c'][0]
            cert_der = base64.b64decode(cert_b64)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            public_key = cert.public_key()
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    raise Exception("Failed to retrieve public key from Keycloak")

# Verificar el token
async def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        public_key = get_keycloak_public_key() 
        payload = jwt.decode(token, public_key, algorithms=['RS256'], audience="account", issuer=f"{KEYCLOAK_SERVER_URL}realms/{REALM_NAME}")
        return payload
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
    
# Dependencia para obtener la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
        
@app.post("/shoes/", response_model=Shoe, dependencies=[Depends(verify_token)])
async def create_shoe_endpoint(shoe: ShoeCreate, db: Session = Depends(get_db)):
    return create_shoe(db, shoe)

@app.get("/shoes/", response_model=List[Shoe], dependencies=[Depends(verify_token)])
async def read_shoes(skip: int = 0, limit: int = 10, db: Session = Depends(get_db)):
    return get_shoes(db, skip=skip, limit=limit)

@app.get("/shoes/{shoe_id}", response_model=Shoe, dependencies=[Depends(verify_token)])
async def read_shoe(shoe_id: int, db: Session = Depends(get_db)):
    db_shoe = get_shoe(db, shoe_id)
    if db_shoe is None:
        raise HTTPException(status_code=404, detail="Shoe not found")
    return db_shoe

@app.put("/shoes/{shoe_id}/stock", response_model=Shoe, dependencies=[Depends(verify_token)])
async def update_stock(shoe_id: int, db: Session = Depends(get_db)):
    db_shoe = update_shoe_stock(db, shoe_id)
    if db_shoe is None:
        raise HTTPException(status_code=404, detail="Shoe not found")
    return db_shoe

@app.delete("/shoes/{shoe_id}", dependencies=[Depends(verify_token)])
async def delete_shoe_endpoint(shoe_id: int, db: Session = Depends(get_db)):
    success = delete_shoe(db, shoe_id)
    if not success:
        raise HTTPException(status_code=404, detail="Shoe not found")
    return {"message": "Shoe deleted successfully"}


# Registro y Log In
def get_role_id(role_name: str):
    roles = keycloak_admin.get_realm_roles()
    for role in roles:
        if role['name'] == role_name:
            return role
    raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")

@app.post("/register")
async def register_user(user: Register):
    try:
        KeycloakAdmin.create_user({
            "email": user.email,
            "username": user.email,
            "enabled": True,
            "credentials": [{"type": "password", "value": user.password, "temporary": False}]
        })
        user_id = keycloak_admin.get_user_id(user.email)

        role = get_role_id("user")

        keycloak_admin.assign_realm_roles(user_id=user_id, roles=[role])

        return {"message": "User created and role assigned successfully"}  
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/sign-in")
async def sign_in(user: UserSignInRequest):
    try:
        token = keycloak_openid.token(
            username=user.email,
            password=user.password,
            grant_type="password"
        )
        return {"access_token": token["access_token"], "refresh_token": token["refresh_token"]}
    except Exception as e:
        # Depurar el error y devolver mensaje claro
        print(f"Error al obtener el token: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid user credentials or Keycloak configuration error.")