from __future__ import annotations

import re
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, TypeVar, cast

from flask import current_app, g, request

from src.auth.validation import normalize_email

from .errors import KvAccessError

F = TypeVar("F", bound=Callable[..., Any])
_EMAIL_RE = re.compile(r"^[^\s/@]+@[^\s/@]+\.[^\s/@]+$")


@dataclass(frozen=True)
class AuthorizedSecretPath:
    path: str
    owner_email: str
    relative_path: str


def _deny(requester_email: str, path: object) -> None:
    # Requirement 1.2 explicitly asks for every denied access to be logged.
    # Keep the client response generic, while the internal log retains evidence.
    current_app.logger.warning(
        "KV_ACCESS_DENIED requester=%s denied_path=%r",
        requester_email or "<unknown>",
        path,
    )
    raise KvAccessError(
        "PERMISSION_DENIED",
        "The requested secret path is unavailable",
        403,
    )


def parse_secret_path(path: object) -> AuthorizedSecretPath:
    """Parse the fixed namespace ``secret/<email>/...`` without touching storage."""

    if not isinstance(path, str):
        raise KvAccessError("INVALID_PATH", "Secret path is invalid", 400)

    candidate = path.strip()
    if (
        not candidate
        or "\x00" in candidate
        or "\\" in candidate
        or candidate.startswith("/")
        or candidate.endswith("/")
        or "//" in candidate
    ):
        raise KvAccessError("INVALID_PATH", "Secret path is invalid", 400)

    parts = candidate.split("/")
    if len(parts) < 3 or parts[0] != "secret":
        raise KvAccessError(
            "INVALID_PATH",
            "Secret paths must use secret/<email>/<name>",
            400,
        )

    owner_email = normalize_email(parts[1])
    relative_parts = parts[2:]
    if (
        not owner_email
        or not _EMAIL_RE.fullmatch(owner_email)
        or any(part in {"", ".", ".."} for part in relative_parts)
    ):
        raise KvAccessError("INVALID_PATH", "Secret path is invalid", 400)

    return AuthorizedSecretPath(
        path="/".join(["secret", owner_email, *relative_parts]),
        owner_email=owner_email,
        relative_path="/".join(relative_parts),
    )


def authorize_secret_path(path: object, requester_email: object) -> AuthorizedSecretPath:
    """Authorize a path before any storage, encryption, or existence lookup.

    A malformed path returns ``INVALID_PATH``. A valid path outside the caller's
    namespace returns one generic ``PERMISSION_DENIED`` response, regardless of
    whether the underlying record exists.
    """

    requester = normalize_email(requester_email)
    parsed = parse_secret_path(path)
    if not requester or parsed.owner_email != requester:
        _deny(requester, path)
    return parsed


def require_owned_secret_path(path_field: str = "path") -> Callable[[F], F]:
    """Reusable guard for Feature 1.1 write/read/delete routes.

    Apply it *inside* ``@require_auth`` so an invalid token is rejected before
    ownership is evaluated::

        @bp.post("/write")
        @require_auth
        @require_owned_secret_path("path")
        def write_secret(): ...

    The normalized authorized path is available as ``g.authorized_secret_path``.
    """

    def decorator(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any):
            if not hasattr(g, "current_user"):
                # This is a developer integration error, not a client auth bypass.
                raise RuntimeError(
                    "require_owned_secret_path must run after require_auth or require_browser_auth"
                )

            body = request.get_json(silent=True)
            path = body.get(path_field) if isinstance(body, dict) else None
            try:
                authorized = authorize_secret_path(
                    path, g.current_user.get("email")
                )
            except KvAccessError as exc:
                return exc.to_response()

            g.authorized_secret_path = authorized.path
            g.authorized_secret_owner = authorized.owner_email
            return view(*args, **kwargs)

        return cast(F, wrapped)

    return decorator
