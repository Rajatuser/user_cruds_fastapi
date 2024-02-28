from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, Time
from sqlalchemy.orm import relationship
from datetime import datetime
from .connection import *

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    name = Column(String(120), unique=False, nullable=True)
    password = Column(String(120), nullable=False)
    role = Column(String(120), nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    last_login = Column(Time, nullable=True)
    created_at = Column(DateTime)
    updated_at = Column(DateTime, default=datetime.utcnow)

class ForgotPasswordToken(Base):  
    __tablename__ = "forgotpasswordtokens"
    id = Column(Integer, primary_key=True)
    user_email = Column(String(120), ForeignKey('users.email'), nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)