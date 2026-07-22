from __future__ import annotations

from flask import Blueprint, g, request

from .db import get_db
from .decorators import require_auth
from .errors import AuthError
from .service import login_user, now_timestamp, register_user, revoke_session

auth_bp = Blueprint("auth", __name__)


def _json_body() -> dict[str, object]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise AuthError("INVALID_JSON", "Request body must be a JSON object", 400)
    return body


@auth_bp.post("/register")
def register():
    try:
        body = _json_body()
        user = register_user(
            get_db(),
            email=body.get("email"),
            passphrase=body.get("passphrase"),
            confirm_passphrase=body.get("confirm_passphrase"),
        )
    except AuthError as exc:
        return exc.to_response()

    return {"user": user}, 201


@auth_bp.post("/login")
def login():
    try:
        body = _json_body()
        result = login_user(
            get_db(),
            email=body.get("email"),
            passphrase=body.get("passphrase"),
        )
    except AuthError as exc:
        return exc.to_response()

    return {
        "token": result.token,
        "token_type": "Bearer",
        "expires_in": int(result.expires_at - now_timestamp()),
        "expires_at": result.expires_at,
        "user": result.user,
    }, 200


@auth_bp.get("/me")
@require_auth
def me():
    return {"user": g.current_user}, 200


@auth_bp.post("/logout")
@require_auth
def logout():
    revoke_session(get_db(), g.session_token_hash)
    return {"message": "Logged out"}, 200
