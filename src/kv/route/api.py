from __future__ import annotations

from flask import Blueprint, g, request

from src.auth.utils import require_auth

from src.kv import authorize_secret_path
from src.kv.utils.engine import kv_obj
from src.kv.utils.errors import KvAccessError

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
    
# @kv_access_api_bp.post("/write")
# @require_auth
# def write_secret():
#     body = request.get_json(silent=True)
#     if not isinstance(body, dict):
#         return {
#             "error": {
#                 "code": "INVALID_JSON",
#                 "message": "Request body must be a JSON object",
#             }
#         }, 400
#     result = None
#     try:
#         path = body.get('path')
#         data = body.get('data')
#         if path and data and g.session_token_hash:
#             result = kv_obj.write(path, data, g.session_token_hash)
#         else:
#             raise ValueError
#     except (KvAccessError, ValueError) as exc:
#         return {
#             "error": {
#                 "code": "INVALID_REQUEST",
#                 "message": "Given request is invalid",
#             }
#         }, 400
#         # return exc.to_response()

#     return result

# @kv_access_api_bp.post("/read")
# @require_auth
# def read_secret():
#     body = request.get_json(silent=True)
#     if not isinstance(body, dict):
#         return {
#             "error": {
#                 "code": "INVALID_JSON",
#                 "message": "Request body must be a JSON object",
#             }
#         }, 400
#     result = None
#     try:
#         path = body.get('path')
#         if path and g.session_token_hash:
#             result = kv_obj.read(path, g.session_token_hash)
#         else:
#             raise ValueError
#     except (KvAccessError, ValueError) as exc:
#         return {
#             "error": {
#                 "code": "INVALID_REQUEST",
#                 "message": "Given request is invalid",
#             }
#         }, 400
#         # return exc.to_response()

#     return result

# @kv_access_api_bp.post("/read")
# @require_auth
# def delete_secret():
#     body = request.get_json(silent=True)
#     if not isinstance(body, dict):
#         return {
#             "error": {
#                 "code": "INVALID_JSON",
#                 "message": "Request body must be a JSON object",
#             }
#         }, 400
#     result = None
#     try:
#         path = body.get('path')
        
#         if path and g.session_token_hash:
#             result = kv_obj.delete(path, g.session_token_hash)
#         else:
#             raise ValueError
#     except (KvAccessError, ValueError) as exc:
#         return {
#             "error": {
#                 "code": "INVALID_REQUEST",
#                 "message": "Given request is invalid",
#             }
#         }, 400
#         # return exc.to_response()

#     return result