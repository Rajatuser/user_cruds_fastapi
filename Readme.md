# About
#### This FastAPI-based User CRUD API provides endpoints to perform basic operations on user data, including creating new users, retrieving user details, updating user information, and deleting user records. JWT token authentication is used for authentication.

## Installation and Requirements:
#### To install requirements:
     pip install -r requirements.txt
#### To run the server
   ##### for development
     uvicorn main:app --reload
  ##### for production
     uvicorn main:app
#### To generate a JWT secret key:
    openssl rand -hex 32