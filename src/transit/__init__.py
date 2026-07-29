from __future__ import annotations

from flask import Flask

from src.extensions import csrf

from .api import transit_api_bp
from .key_store import wrap_key_material
from .service import decrypt_for_user, encrypt_for_user
from .web import transit_web_bp


def init_transit_encrypt_decrypt(app: Flask) -> None:
    app.config.setdefault("TRANSIT_MAX_PLAINTEXT_BYTES", 1024 * 1024)
    app.config.setdefault("ENABLE_TRANSIT_DEMO_KEY", False)

    # Import the shared 2.1/2.2 model before db.create_all or migrations.
    from . import models as _models  # noqa: F401

    app.register_blueprint(transit_api_bp, url_prefix="/api/transit")
    app.register_blueprint(transit_web_bp, url_prefix="/transit")
    csrf.exempt(transit_api_bp)


__all__ = [
    "decrypt_for_user",
    "encrypt_for_user",
    "init_transit_encrypt_decrypt",
    "wrap_key_material",
]
