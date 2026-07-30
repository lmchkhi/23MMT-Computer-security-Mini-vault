from __future__ import annotations

from dataclasses import dataclass
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INSTANCE_PATH = PROJECT_ROOT / "instance"


@dataclass
class Config:
    SECRET_KEY: str
    WTF_CSRF_SECRET_KEY: str
    SQLALCHEMY_DATABASE_URI: str
    TEMPLATE_FOLDER_LOCATION: str
    STATIC_FOLDER_LOCATION: str
    INSTANCE_PATH: str
    AUTH_TOKEN_TTL_SECONDS: int
    AUTH_LOCKOUT_SECONDS: int
    AUTH_MAX_FAILED_ATTEMPTS: int
    AUTH_COOKIE_NAME: str
    AUTH_COOKIE_SECURE: bool
    ENABLE_TRANSIT_DEMO_KEY: bool
    TRANSIT_MAX_PLAINTEXT_BYTES: int


@dataclass
class DefaultConfig(Config):
    """Runtime defaults that are safe to import in tests and fresh clones.

    Environment variables still override the defaults, but importing the app no
    longer crashes merely because ``VIRTUAL_ENV`` or a local ``.env`` is absent.
    """

    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(32)
    WTF_CSRF_SECRET_KEY = os.getenv("WTF_CSRF_SECRET_KEY") or secrets.token_urlsafe(32)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "SQLALCHEMY_DATABASE_URI",
        f"sqlite:///{(DEFAULT_INSTANCE_PATH / 'mini-vault.db').as_posix()}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    TEMPLATE_FOLDER_LOCATION = str(PROJECT_ROOT / "templates")
    STATIC_FOLDER_LOCATION = str(PROJECT_ROOT / "static")
    INSTANCE_PATH = str(DEFAULT_INSTANCE_PATH)

    REMEMBER_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SAMESITE = "Strict"
    AUTH_TOKEN_TTL_SECONDS = 30 * 60
    AUTH_LOCKOUT_SECONDS = 5 * 60
    AUTH_MAX_FAILED_ATTEMPTS = 5
    AUTH_COOKIE_NAME = "mini_vault_session"
    AUTH_COOKIE_SECURE = False

    ENABLE_TRANSIT_DEMO_KEY = False
    TRANSIT_MAX_PLAINTEXT_BYTES = 1024 * 1024


@dataclass
class TestConfig:
    pass
