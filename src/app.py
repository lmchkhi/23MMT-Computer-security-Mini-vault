from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify

from src.auth import init_auth
from src.auth.decorators import require_auth


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create a standalone Flask app for Feature 0.2.

    Other branches do not need to use this factory. They can import and call
    ``init_auth(existing_app)`` on their own Flask application instead.
    """
    app = Flask(__name__)

    default_db = Path(os.getenv("MINI_VAULT_DB", "data/minivault.db"))
    app.config.from_mapping(
        AUTH_DATABASE=str(default_db),
        AUTH_TOKEN_TTL_SECONDS=30 * 60,
        AUTH_LOCKOUT_SECONDS=5 * 60,
        AUTH_MAX_FAILED_ATTEMPTS=5,
    )

    if test_config:
        app.config.update(test_config)

    init_auth(app)

    @app.get("/health")
    def health() -> tuple[dict[str, str], int]:
        return {"status": "ok"}, 200

    @app.get("/api/protected-example")
    @require_auth
    def protected_example() -> tuple[dict[str, object], int]:
        """Example showing how Feature 1 and Feature 2 should require auth."""
        from flask import g

        return {
            "message": "Authenticated request accepted",
            "current_user": g.current_user,
        }, 200

    @app.errorhandler(404)
    def not_found(_: Exception):
        return jsonify({"error": {"code": "NOT_FOUND", "message": "Endpoint not found"}}), 404

    return app
