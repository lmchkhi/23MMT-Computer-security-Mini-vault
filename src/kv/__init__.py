from __future__ import annotations

from flask import Flask

from src.extensions import csrf

from .access_control import authorize_secret_path, require_owned_secret_path
from .api import kv_access_api_bp
from .web import kv_access_web_bp


def init_kv_access_control(app: Flask) -> None:
    app.register_blueprint(kv_access_api_bp, url_prefix="/api/kv/access")
    app.register_blueprint(kv_access_web_bp, url_prefix="/kv/access-control")
    csrf.exempt(kv_access_api_bp)


__all__ = [
    "authorize_secret_path",
    "init_kv_access_control",
    "require_owned_secret_path",
]
