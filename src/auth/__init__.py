from __future__ import annotations

from flask import Flask

from src.extensions import csrf

from .api import auth_api_bp
from .decorators import require_auth
from .web import auth_web_bp


def init_auth(app: Flask) -> None:
    """Attach Feature 0.2 to an app using the team's shared extensions."""

    app.config.setdefault("AUTH_TOKEN_TTL_SECONDS", 30 * 60)
    app.config.setdefault("AUTH_LOCKOUT_SECONDS", 5 * 60)
    app.config.setdefault("AUTH_MAX_FAILED_ATTEMPTS", 5)
    app.config.setdefault("AUTH_COOKIE_NAME", "mini_vault_session")
    app.config.setdefault("AUTH_COOKIE_SECURE", False)

    # Import models before the final db.create_all()/migration step.
    from . import models as _models  # noqa: F401

    app.register_blueprint(auth_api_bp, url_prefix="/api/auth")
    app.register_blueprint(auth_web_bp, url_prefix="/auth")

    # The JSON API does not use browser cookies. Bearer tokens protect private
    # endpoints, so Flask-WTF CSRF remains enabled only for server-rendered forms.
    csrf.exempt(auth_api_bp)


__all__ = ["init_auth", "require_auth"]
