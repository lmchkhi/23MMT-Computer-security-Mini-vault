from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from flask import Flask, redirect, request, url_for

from src.auth import init_auth
from src.extensions import csrf, db
from src.kv import init_kv_access_control
from src.transit import init_transit_encrypt_decrypt
from src.workspace import init_workspace_ui

load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create the merge-oriented Mini Vault Flask application.

    All features share exactly one Flask-SQLAlchemy instance and one CSRF
    extension. The blueprints remain isolated so they can be reviewed or moved
    into the team's integration branch without rewriting authentication.
    """

    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    default_database = Path(app.instance_path) / "mini_vault.db"
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-me"),
        SQLALCHEMY_DATABASE_URI=os.getenv(
            "SQLALCHEMY_DATABASE_URI", f"sqlite:///{default_database.as_posix()}"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        AUTH_TOKEN_TTL_SECONDS=30 * 60,
        AUTH_LOCKOUT_SECONDS=5 * 60,
        AUTH_MAX_FAILED_ATTEMPTS=5,
        AUTH_COOKIE_NAME="mini_vault_session",
        AUTH_COOKIE_SECURE=_env_bool("AUTH_COOKIE_SECURE", False),
        ENABLE_TRANSIT_DEMO_KEY=_env_bool("ENABLE_TRANSIT_DEMO_KEY", False),
        TRANSIT_MAX_PLAINTEXT_BYTES=1024 * 1024,
        WTF_CSRF_TIME_LIMIT=None,
    )

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    csrf.init_app(app)

    # Register shared UI assets first, then feature blueprints.
    init_workspace_ui(app)
    init_auth(app)
    init_kv_access_control(app)
    init_transit_encrypt_decrypt(app)

    # Importing feature models occurs inside the init functions.
    with app.app_context():
        db.create_all()

    @app.get("/")
    def index():
        return redirect(url_for("auth_web.account"))

    @app.get("/health")
    def health() -> tuple[dict[str, object], int]:
        return {
            "status": "ok",
            "features": ["0.2-user-auth", "1.2-kv-access-control", "2.2-transit"],
        }, 200

    @app.errorhandler(404)
    def not_found(_: Exception):
        if request.path.startswith("/api/"):
            return {
                "error": {"code": "NOT_FOUND", "message": "Endpoint not found"}
            }, 404
        return redirect(url_for("auth_web.login"))

    return app
