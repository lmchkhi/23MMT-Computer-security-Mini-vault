from __future__ import annotations

from flask import Blueprint, g, request

from src.auth import require_auth

from .errors import TransitError
from .service import decrypt_for_user, encrypt_for_user

transit_api_bp = Blueprint("transit_api", __name__)


def _json_body() -> dict[str, object]:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise TransitError(
            "INVALID_JSON", "Request body must be a JSON object", 400
        )
    return body


@transit_api_bp.post("/encrypt")
@require_auth
def encrypt():
    try:
        body = _json_body()
        result = encrypt_for_user(
            owner_email=g.current_user.get("email"),
            key_name=body.get("key_name"),
            plaintext_b64=body.get("plaintext_b64"),
        )
    except TransitError as exc:
        return exc.to_response()

    return {
        "key_name": result.key_name,
        "ciphertext": result.ciphertext,
    }, 200


@transit_api_bp.post("/decrypt")
@require_auth
def decrypt():
    try:
        body = _json_body()
        result = decrypt_for_user(
            owner_email=g.current_user.get("email"),
            ciphertext=body.get("ciphertext"),
        )
    except TransitError as exc:
        return exc.to_response()

    return {
        "key_name": result.key_name,
        "plaintext_b64": result.plaintext_b64,
    }, 200
