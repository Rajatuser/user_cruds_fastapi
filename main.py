from fastapi import Depends, FastAPI, HTTPException, status, Body
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError, validator, EmailStr, root_validator
from typing import Union
from database_connections.models import Users
from database_connections.connection import *
from fastapi.middleware.cors import CORSMiddleware
from database_connections.models import *
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from typing_extensions import Annotated



SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()
db = SessionLocal()
origins = [
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

####################### helper auth functions #######################

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password):
    return pwd_context.hash(password)

def email_exists(user_email):
    email_ex = db.query(Users).filter_by(email=user_email).first()
    return email_ex

def authenticate_user(email,password):
    user_identity = email_exists(email)
    if user_identity is not None:
        if verify_password(password, user_identity.password):
            return user_identity
    return False

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username

################## Validations #################################
class Users_cred(BaseModel):
    email: str
    password: str
    role: str
    active: bool = True

    @validator("password")
    def hash_password(cls, v):
        return hash_password(v)

class login(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Update_user_info(BaseModel):
    email: EmailStr = None
    password: str = None
    role: str = None
    active: str = None
 
    @root_validator(pre=True)
    def at_least_one_field_required(cls, values):
        required_fields = ["email", "password", "role", "active"]
        present_fields = [field for field in required_fields if values.get(field) is not None]
        if not present_fields:
            raise ValueError(f"At least one of {required_fields} is required")
        return values


###################### User API's ###########################

"""
This API creates user
Method: POST
"""
@app.post('/register_user')
def register_user(user_credentials: Users_cred = Body()):
    try:
        user = Users(**user_credentials.dict(), created_at=datetime.utcnow())
        db.add(user)
        db.commit()
        return JSONResponse(content={'message':'User registered successfully'}, status_code=200)
    except ValidationError as e:
        return {"error": e.errors()}
    
"""
This API login user
Method: POST
"""
@app.post('/login')
def login_user(login_creds: Annotated[login, Body()]) -> Token:
    authenticate_current_user = authenticate_user(login_creds.email, login_creds.password)
    if not authenticate_current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": authenticate_current_user.email}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

"""
This API gets all users
Method: GET
"""
@app.get('/users')
def get_users(current_user: str = Depends(get_current_user)):
    data = db.query(Users).all()
    all_users = []
    for user in data:
        users_dict = {
            "id":user.id,
            "email":user.email,
            "role":user.role,
            "active":user.active
        }
        all_users.append(users_dict)
    return JSONResponse(content={'message':'data Found','data': all_users}, status_code=200)


"""
This API updates user information
METHOD: PATCH
"""
@app.patch('/update_user_info/{user_id}')
def update_user(user_id: int, update_credentials: Update_user_info = Body(),current_user: str = Depends(get_current_user)):
    user_exists = db.query(Users).get(user_id)
    if user_exists is not None:
        if update_credentials.email is not None:
            user_exists.email = update_credentials.email
        if update_credentials.password is not None:
            user_exists.password = hash_password(update_credentials.password)
        if update_credentials.role is not None:
            user_exists.role = update_credentials.role
        if update_credentials.active is not None:
            user_exists.active = bool(update_credentials.active)
        db.commit()
        return JSONResponse(content={'message':'User updated successfully'}, status_code=200)
    else:
        return JSONResponse(content={'message':'User not found'}, status_code=404)

"""
This API deletes user
"""
@app.delete('/delete_user/{user_id}')
def delete_user(user_id:int,current_user: str = Depends(get_current_user)):
    user_exists = db.query(Users).get(user_id)
    if user_exists is not None:
        db.delete(user_exists)
        db.commit()
        return JSONResponse(content={'message':'User deleted successfully'}, status_code=200)
    else:
        return JSONResponse(content={'message':'User not found'}, status_code=404)
