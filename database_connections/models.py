from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, Time
from sqlalchemy.orm import relationship
from datetime import datetime
from .connection import *

class Users(Base):
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

Base.metadata.create_all(bind=engine)