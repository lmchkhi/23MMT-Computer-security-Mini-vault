from __future__ import annotations

from flask import Flask

from .db import init_app as init_db
from .decorators import require_auth
from .routes import auth_bp


def init_auth(app: Flask) -> None:
    """Attach Feature 0.2 to an existing Flask application.

    This is the only integration call other branches need.
    """
    app.config.setdefault("AUTH_DATABASE", "data/minivault.db")
    app.config.setdefault("AUTH_TOKEN_TTL_SECONDS", 30 * 60)
    app.config.setdefault("AUTH_LOCKOUT_SECONDS", 5 * 60)
    app.config.setdefault("AUTH_MAX_FAILED_ATTEMPTS", 5)

    init_db(app)
    app.register_blueprint(auth_bp, url_prefix="/api/auth")


__all__ = ["init_auth", "require_auth"]
