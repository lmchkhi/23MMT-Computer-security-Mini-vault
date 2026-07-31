from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar, cast
from flask import current_app, flash, g, redirect, request, url_for

from .errors import AuthError
from .service import authenticate_token

F = TypeVar("F", bound=Callable[..., Any])


def _extract_bearer_token() -> str:
    header = request.headers.get("Authorization", "")
    scheme, separator, token = header.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token.strip():
        raise AuthError(
            "UNAUTHENTICATED", "A Bearer session token is required", 401
        )
    return token.strip()


def _load_context(raw_token: str) -> None:
    context = authenticate_token(raw_token)
    g.current_user = context.user.to_public_dict()
    g.auth_user = context.user
    g.session_token_hash = context.token_hash
    g.session_expires_at = context.expires_at


def require_auth(view: F) -> F:
    """Protect JSON/API endpoints with an Authorization: Bearer token."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        try:
            _load_context(_extract_bearer_token())
        except AuthError as exc:
            return exc.to_response()
        return view(*args, **kwargs)

    return cast(F, wrapped)


def require_browser_auth(view: F) -> F:
    """Protect server-rendered pages with the same opaque token in a cookie."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        cookie_name = current_app.config["AUTH_COOKIE_NAME"]
        raw_token = request.cookies.get(cookie_name, "")
        try:
            _load_context(raw_token)
        except AuthError as exc:
            if exc.code == "SESSION_EXPIRED":
                flash("Your session expired. Log in again.", "warning")
            elif raw_token:
                flash("Your session is no longer valid. Log in again.", "warning")
            
            next_path = request.full_path if request.query_string else request.path
            response = redirect(
                url_for("auth.login", next=next_path)
            )
            response.delete_cookie(cookie_name, path="/")
            return response
        return view(*args, **kwargs)

    return cast(F, wrapped)
