from __future__ import annotations

from flask import Blueprint, g, request

from src.auth import require_auth

from .access_control import authorize_secret_path
from .errors import KvAccessError

kv_access_api_bp = Blueprint("kv_access_api", __name__)


@kv_access_api_bp.post("/check")
@require_auth
def check_access():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return {
            "error": {
                "code": "INVALID_JSON",
                "message": "Request body must be a JSON object",
            }
        }, 400

    try:
        authorized = authorize_secret_path(
            body.get("path"), g.current_user.get("email")
        )
    except KvAccessError as exc:
        return exc.to_response()

    return {
        "authorized": True,
        "path": authorized.path,
        "owner_email": authorized.owner_email,
    }, 200
