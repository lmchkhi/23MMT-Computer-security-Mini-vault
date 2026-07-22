from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar, cast

from flask import g, request

from .db import get_db
from .errors import AuthError
from .service import authenticate_token

F = TypeVar("F", bound=Callable[..., Any])


def _extract_bearer_token() -> str:
    header = request.headers.get("Authorization", "")
    scheme, separator, token = header.partition(" ")

    if separator != " " or scheme.lower() != "bearer" or not token.strip():
        raise AuthError(
            "UNAUTHENTICATED",
            "A Bearer session token is required",
            401,
        )
    return token.strip()


def require_auth(view: F) -> F:
    """Require a valid session and expose the identity through Flask ``g``.

    Feature 1 and Feature 2 routes should place this decorator closest to the
    function, after their Flask route decorator.
    """

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any):
        try:
            user, digest = authenticate_token(get_db(), _extract_bearer_token())
        except AuthError as exc:
            return exc.to_response()

        g.current_user = user
        g.session_token_hash = digest
        return view(*args, **kwargs)

    return cast(F, wrapped)
