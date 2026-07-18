from dotenv import load_dotenv
from dataclasses import dataclass
import os

load_dotenv()

@dataclass
class Config:
    SECRET_KEY: str
    WTF_CSRF_SECRET_KEY: str
    SQLALCHEMY_DATABASE_URI: str
    TEMPLATE_FOLDER_LOCATION: str
    STATIC_FOLDER_LOCATION: str
    INSTANCE_PATH: str
    
    
@dataclass
class DefaultConfig(Config):
    SECRET_KEY = os.environ["SECRET_KEY"]
    WTF_CSRF_SECRET_KEY = os.environ["WTF_CSRF_SECRET_KEY"]
    SQLALCHEMY_DATABASE_URI = os.environ["SQLALCHEMY_DATABASE_URI"]
    TEMPLATE_FOLDER_LOCATION = os.path.normpath(os.path.join(os.environ['VIRTUAL_ENV'],'..','templates'))
    STATIC_FOLDER_LOCATION = os.path.normpath(os.path.join(os.environ['VIRTUAL_ENV'],'..','static'))
    INSTANCE_PATH = os.path.normpath(os.path.join(os.environ['VIRTUAL_ENV'],'..','instance'))
    REMEMBER_COOKIE_SAMESITE = "strict"
    SESSION_COOKIE_SAMESITE = "strict"
@dataclass
class TestConfig:
    pass