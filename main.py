from fastapi import Depends, FastAPI, HTTPException, status, Body , Query , Response , Request
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError, validator, EmailStr, root_validator, Extra, Field
from typing import List, Union
from database_connections.models import Users
from database_connections.connection import *
from fastapi.middleware.cors import CORSMiddleware
from database_connections.models import *
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from typing_extensions import Annotated
import os
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from htmlTemplates import forgot_template
import re
from typing import List
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder


load_dotenv()


SECRET_KEY = os.getenv('JWT_SECRET_KEY')
ALGORITHM = os.getenv("JWT_ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

####### Email Configurations######

conf = ConnectionConfig(
    MAIL_USERNAME = str(os.getenv('MAIL_FROM')),
    MAIL_PASSWORD = str(os.getenv('MAIL_PASSWORD')),
    MAIL_FROM = str(os.getenv('MAIL_FROM')),
    MAIL_PORT = 587,
    MAIL_SERVER = str(os.getenv("MAIL_SERVER")),
    MAIL_FROM_NAME="hanish",
    MAIL_STARTTLS = True,
    MAIL_SSL_TLS = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = False
)


app = FastAPI()
db = SessionLocal()
origins = [
    "http://localhost:3000",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    try:
        email_ex = db.query(Users).filter_by(email=user_email).first()
        return email_ex
    except:
        return None

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
pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,15}$')
name_pattern =  re.compile(r'^[a-zA-Z]+(?: [a-zA-Z]+)?$')
email_pattern = re.compile(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$')

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = {}
    for error in exc.errors():
        error_message = [msg.strip() for msg in error['msg'].split(',')]
        if error_message[0] == 'Value error':
           error_message.pop(0)
           errors[error['loc'][1]] = error_message
        elif error['type'] == 'extra_forbidden':
            errors[error['loc'][1]] = ["Extra fields are not allowed"]
        elif error['type'] == 'missing':
            errors[error['loc'][1]] = f"{error['loc'][1]} field is required"
        else:
            errors[error['loc'][1]] = error_message
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({"message": {'validation_errors':errors} , 'success':False , 'statusCode' : 422}),
    )

class Users_cred(BaseModel):
    email: EmailStr
    password: str
    role: str
    active: bool = True
    name: str = None
    
    @validator("email", pre=True)
    def validate_email(cls, v):
        if not v:
            raise ValueError("Email cannot be empty")
        if not email_pattern.match(v):
            raise ValueError("Email format is invalid. Eg.company@domain.com")
        return v
    
    @validator("role")
    def validate_role(cls, v):
        if not v.strip():
            raise ValueError("Role cannot be empty")
        if ' ' in v:
            raise ValueError("Spaces are not allowed")
        if v not in {"user", "admin", "superadmin"}:
           raise ValueError("Please select atleast one role: user or admin or superadmin")
        return v.strip()
    
    @validator("name")
    def validate_name(cls , v):
        if not name_pattern.match(v):
            raise ValueError("Name can only contains alphabets.")
        return v
    
    @validator("password")
    def validate_password(cls, v):
        if not v.strip():
            raise ValueError("Password cannot be empty")
        if ' ' in v or '.' in v:
            raise ValueError("Password cannot contain spaces and dot")
        if len(v) > 15:
             raise ValueError("Password length must not exceed 15 characters")
        if not pattern.match(v):
            raise ValueError("Password must be 8 characters long and contain at least one uppercase, one lowercase, one number, and one special character")
        return v
    
    @validator("password")
    def hash_password(cls, v):
        return hash_password(v)
    class Config:
        extra = Extra.forbid

class updated_password(BaseModel):
    password: str

    @validator("password")
    def validate_password(cls, v):
        if not v.strip():
            raise ValueError("Password cannot be empty")
        if ' ' in v:
            raise ValueError("Password cannot contain spaces")
        if len(v) > 15:
             raise ValueError("Password length must not exceed 15 characters")
        if not pattern.match(v):
            raise ValueError("Password must be 8 characters long and contain at least one uppercase, one lowercase, one number, and one special character")
        return v
    
    @validator("password")
    def hash_password(cls, v):
        return hash_password(v)

class change_password(BaseModel):
    old_password: str
    new_password: str

    @validator("old_password")
    def validate_old_password(cls, v):
        if not v.strip():
            raise ValueError("Old Password cannot be empty")
        return v

    @validator("new_password")
    def validate_password(cls, v):
        if not v.strip():
            raise ValueError("New password cannot be empty")
        if ' ' in v:
            raise ValueError("New Password cannot contain spaces")
        if len(v) > 15:
             raise ValueError("New Password length must not exceed 15 characters")
        if not pattern.match(v):
            raise ValueError("New Password must be 8 characters long and contain at least one uppercase, one lowercase, one number, and one special character")
        return v
    
    @validator("new_password")
    def hash_password(cls, v):
        return hash_password(v)

class login(BaseModel):
    email: EmailStr
    password: str

    @validator("email", pre=True)
    def validate_email(cls, v):
        if not v:
            raise ValueError("Email is required")
        if not email_pattern.match(v):
            raise ValueError("Email format is invalid. Eg.company@domain.com")
        return v

    @validator("password")
    def validate_password(cls, v):
        if not v.strip():
            raise ValueError("Password is required")
        if ' ' in v:
            raise ValueError("Password cannot contain spaces")
        if len(v) > 15:
             raise ValueError("Password length must not exceed 15 characters")
        return v
    class Config:
        extra = Extra.forbid

class Token(BaseModel):
    access_token: str
    token_type: str
    
    class Config:
        extra = Extra.forbid

class Forgot_password(BaseModel):
    email: EmailStr

    @validator("email", pre=True)
    def validate_email(cls, v):
        if not v:
            raise ValueError("Email cannot be empty")
        if not email_pattern.match(v):
            raise ValueError("Email format is invalid. Eg.company@domain.com")
        return v
    class Config:
        extra = Extra.forbid

class EmailSchema(BaseModel):
    email: List[EmailStr]

    @validator("email", pre=True)
    def validate_email(cls, v):
        if not isinstance(v , List):
            raise ValueError("Email should be in List.")
        if len(v) == 0:
            raise ValueError("Email cannot be empty")
        for emails in v:
            if len(emails) == 0:
                raise ValueError("Empty emails are not allowed")
            if not email_pattern.match(emails):
                raise ValueError("Email format is invalid.")
        return v

    class Config:
        extra = Extra.forbid

class Update_user_info(BaseModel):
    email: EmailStr = None
    password: str = None
    role: str = None
    active: bool = True
    name: str = None

    @validator("email", pre=True)
    def validate_email(cls, v):
        if not v:
            raise ValueError("Email cannot be empty")
        if not email_pattern.match(v):
            raise ValueError("Email format is invalid. Eg.company@domain.com")
        return v

    @validator("name")
    def validate_name(cls , v):
        if not name_pattern.match(v):
            raise ValueError("Name can only contains alphabets.")
        return v
 
    @root_validator(pre=True)
    def at_least_one_field_required(cls, values):
        required_fields = ["email", "password", "role", "active"]
        present_fields = [field for field in required_fields if values.get(field) is not None]
        if not present_fields:
            raise ValueError(f"At least one of {required_fields} is required")
        return values

    @validator("role")
    def validate_role(cls, v):
        if not v.strip():
            raise ValueError("Role cannot be empty")
        if v not in {"user", "admin", "superadmin"}:
            raise ValueError("Please select atleast one role: user or admin or superadmin")
        return v.strip()
    
    @validator("password")
    def validate_password(cls, v):
        if not v.strip():
            raise ValueError("Password cannot be empty")
        if ' ' in v:
            raise ValueError("Password cannot contain spaces")
        if len(v) > 15:
             raise ValueError("Password length must not exceed 15 characters")
        if not pattern.match(v):
            raise ValueError("Password must be 8 characters long and contain at least one uppercase, one lowercase, one number, and one special character")
        return v
    
    @validator("password")
    def hash_password(cls, v):
        return hash_password(v)
    
    class Config:
        extra = Extra.forbid
        



###################### User API's ###########################
        

def get_pagination_params(
    page: Union[int, str] = None ,
    per_page: int = Query(10, gt=0)
):
    if not page:
        page = 1
    return {"page": page, "per_page": per_page}

"""
This API creates user
Method: POST
"""
@app.post('/register_user')
def register_user(user_credentials: Users_cred = Body()):
    try:
        user_exists = db.query(Users).filter_by(email=user_credentials.email).first()
        if user_exists is None:
            user = Users(**user_credentials.dict(), created_at=datetime.utcnow())
            db.add(user)
            db.commit()
            return JSONResponse(content={'message':'User registered successfully','status_code':201 , 'success':True}, status_code=201)
        else:
            return JSONResponse(content={'message':{'validation_errors':{'email':['The email has already been taken']}}, 'status_code':409 , 'success':False}, status_code=409)
    except ValidationError as e:
         db.rollback() 
         return JSONResponse(content={'message':'Server Error', 'status_code':500 , 'success':False}, status_code=500)
    
"""
This API login user
Method: POST
"""
@app.post('/login')
def login_user(login_creds: Annotated[login, Body()]) -> Token:
    authenticate_current_user = authenticate_user(login_creds.email, login_creds.password)
    if not authenticate_current_user:
        return JSONResponse(content={"message":{'validation_errors':["User credentials are incorrect"]},'status_code':404 , 'success':False}, status_code=404)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": authenticate_current_user.email}, expires_delta=access_token_expires
    )
    return JSONResponse(content={"message":"Login Success","token":access_token,"token_type":"bearer",'status_code':200 , 'success':True},status_code=200)


"""
This API get user information
METHOD: POST
"""
@app.get('/user_info')
def user_information(current_user: str = Depends(get_current_user)):
    user_info = db.query(Users).filter_by(email=current_user).first()
    if user_info:
        user_info_dict = {
                "id":user_info.id,
                "email":user_info.email,
                "role":user_info.role,
                "active":user_info.active
        }
        return JSONResponse(content={'message':'data Found','data': user_info_dict, 'status_code':200 , 'success':True}, status_code=200)
    else:
        return JSONResponse(content={'message':'no data found','data': [],'status_code':204 , 'success':True}, status_code=404)
        

"""
This API gets all users
Method: GET
"""
@app.get('/users', response_model=List[str])
def get_users(response: Response,pagination: dict = Depends(get_pagination_params),current_user: str = Depends(get_current_user)):
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
    page = pagination["page"]
    per_page = pagination["per_page"]
    start = (page - 1) * per_page
    end = start + per_page
    if len(all_users[start:end]) > 0:
        return JSONResponse(content={'message':'data Found','data': all_users[start:end], 'current_page':page ,'total_pages':int(len(all_users)/10+1),'status_code':200 , 'success':True}, status_code=200)
    else:
        return JSONResponse(content={'message':'no data Found','data': all_users[start:end], 'current_page':page ,'total_pages':int(len(all_users)/10+1),'status_code':404 , 'success':False}, status_code=404)


"""
This API updates user information
METHOD: PATCH
"""
@app.patch('/update_user_info/{user_id}')
def update_user(user_id: int, update_credentials: Update_user_info = Body(),current_user: str = Depends(get_current_user)):
    user_exists = db.query(Users).get(user_id)
    if user_exists is not None:
        if update_credentials.email is not None:
            email_exists = db.query(Users).filter_by(email=update_credentials.email).first()
            if email_exists:
                return JSONResponse(content={'message':{'validation_errors':{'email':['The email has already been taken']}}}, status_code=409)
            user_exists.email = update_credentials.email
        if update_credentials.password is not None:
            user_exists.password = hash_password(update_credentials.password)
        if update_credentials.role is not None:
            user_exists.role = update_credentials.role
        if update_credentials.active is not None:
            user_exists.active = bool(update_credentials.active)
        db.commit()
        return JSONResponse(content={'message':'User updated successfully','status_code':200 , 'success':True}, status_code=200)
    else:
        db.rollback() 
        return JSONResponse(content={"message": {"validation_errors":{"id":["User not found"]}}, 'status_code':404 , 'success':False}, status_code=404)

"""
This API deletes user
"""
@app.delete('/delete_user/{user_id}')
def delete_user(user_id:int,current_user: str = Depends(get_current_user)):
    user_exists = db.query(Users).get(user_id)
    if user_exists is not None:
        db.delete(user_exists)
        db.commit()
        return JSONResponse(content={'message':'User deleted successfully','status_code':200 , 'success':True}, status_code=200)
    else:
        return JSONResponse(content={"message": {"validation_errors":{"id":["User not found"]}}, 'status_code':404 , 'success':False}, status_code=404)


"""
Forgot password API
"""
@app.post('/forgot_password')
async def forgot_password(email: EmailSchema) -> JSONResponse:
    html = forgot_template()
    access_token_expires = timedelta(minutes=10)
    access_token = create_access_token(
        data={"sub": email.dict().get("email")[0]}, expires_delta=access_token_expires
    )
    updated_template = html.replace('{email}',email.dict().get("email")[0]).replace('{change_password_link}',f"{os.getenv('CHANGE_PASSWORD_ENDPOINT')}/changePassword/{access_token}")
    message = MessageSchema(
        subject="Password Reset",
        recipients=email.dict().get("email"),
        body=updated_template,
        subtype=MessageType.html)

    fm = FastMail(conf)
    await fm.send_message(message)
    return JSONResponse(status_code=200, content={"message": "Reset Link is sent on your email.",'status_code':200 , 'success':True})


"""
This API check if user exists for password change
"""
@app.get('/authorize_user')
def change_password_page(current_user: str = Depends(get_current_user)):
        return JSONResponse(content={"message":"User Found", 'status_code':200 , 'success':True}, status_code=200)
    # else:
    #     return JSONResponse(content={"message":"User not Found"}, status_code=200)

"""
This API updates password
"""
@app.post('/update_password')
def update_user_password(updated_user_password:updated_password,current_user: str = Depends(get_current_user)):
    if updated_user_password.password is not None:
        user_exists = db.query(Users).filter_by(email=current_user).first()
        if user_exists:
            user_exists.password = updated_user_password.password
            db.commit()
            return JSONResponse(status_code=200, content={"message": "Password Updated Successfully", 'status_code':200 , 'success':True})
        else:
            return JSONResponse(status_code=404, content={"message": {"validation_errors":{"email":["User not found"]}}, 'status_code':404 , 'success':False})
                

"""
This API changes password
"""
@app.post('/change_password')
def update_user_password(change_password:change_password,current_user: str = Depends(get_current_user)):
    user_exists = db.query(Users).filter_by(email=current_user).first()
    if user_exists:
        old_password_verify = verify_password(change_password.old_password, user_exists.password)
        if old_password_verify:
            if change_password.new_password is not None:
                    user_exists.password = change_password.new_password
                    db.commit()
                    return JSONResponse(status_code=200, content={"message": "Password Updated Successfully", 'status_code':200 , 'success':True})
        else:
             return JSONResponse(status_code=401, content={"message":["Old password is incorrect."], 'status_code':401 , 'success':False})
    else:
        return JSONResponse(status_code=404, content={"message": {"validation_errors":{"email":["User not found"]}}, 'status_code':404 , 'success':False})


