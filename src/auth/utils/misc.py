from flask import request, current_app
from .errors import AuthError
from .service import login_user
from src.storage import User
from src.auth.form import RegistrationForm
from urllib.parse import urlparse, urljoin

def is_safe_url(url, alternitive_url=None):
    # if alternitive_url is None:
    #     alternitive_url = current_app.config.get('SERVER_NAME')
    try:
        ref_url = urlparse(alternitive_url or request.host_url)

        test_url = urlparse(urljoin(request.host_url, url))
        return (
            test_url.scheme in ('http', 'https') and 
            ref_url.netloc == test_url.netloc
        )
    except Exception:
        return False

def get_valid_next_url(next_url:str|None):
    if next_url and is_safe_url(next_url):
        next = next_url
    else:
        next = None
    return next

def _user_login(user: User, response):
    result = login_user(user=user)
    response.set_cookie(
        current_app.config["AUTH_COOKIE_NAME"],
        result.token,
        max_age=int(current_app.config["AUTH_TOKEN_TTL_SECONDS"]),
        httponly=True,
        secure=bool(current_app.config["AUTH_COOKIE_SECURE"]),
        samesite="Strict",
        path="/",
    )
    return response

def _append_field_errors(form: RegistrationForm, error: AuthError) -> None:
    fields = error.details.get("fields", {})
    if not isinstance(fields, dict):
        return
    for field_name, messages in fields.items():
        field = getattr(form, field_name, None)
        if field is None or not isinstance(messages, list):
            continue
        field.errors = list(field.errors) + [str(message) for message in messages]
        
__all__ =['_append_field_errors', '_user_login', 'get_valid_next_url']