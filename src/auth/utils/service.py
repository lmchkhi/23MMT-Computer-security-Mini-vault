from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import current_app
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from src.app import db

from .errors import AuthError
from src.storage import AuthSession, User
from .validation import normalize_email, validate_email, validate_passphrase

PASSWORD_HASHER = PasswordHasher()


@dataclass(frozen=True)
class LoginResult:
    token: str
    expires_at: int
    user: dict[str, object]


@dataclass(frozen=True)
class AuthContext:
    user: User
    token_hash: str
    expires_at: int


def now_timestamp() -> int:
    """Return UTC epoch seconds; tests can inject a deterministic clock."""

    clock = current_app.config.get("AUTH_CLOCK", time.time)
    return int(clock())


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def register_user(
    *,
    email: object,
    passphrase: object,
    confirm_passphrase: object,
) -> dict[str, object]:
    
    """
    Check and Register a user to database
    """
    normalized_email = normalize_email(email)

    field_errors: dict[str, list[str]] = {}
    email_errors = validate_email(normalized_email)
    passphrase_errors = validate_passphrase(passphrase)
    
    if email_errors:
        field_errors["email"] = email_errors
    if passphrase_errors:
        field_errors["passphrase"] = passphrase_errors
    if passphrase != confirm_passphrase:
        field_errors.setdefault("confirm_passphrase", []).append(
            "Passphrase confirmation does not match"
        )

    if field_errors:
        raise AuthError(
            "VALIDATION_ERROR",
            "Registration data is invalid",
            400,
            {"fields": field_errors},
        )

    timestamp = now_timestamp()
    user = User(
        email=normalized_email, #type: ignore
        password_hash=PASSWORD_HASHER.hash(passphrase),#type: ignore
        failed_attempts=0,#type: ignore
        lock_until=None,#type: ignore
        created_at=timestamp,#type: ignore
        updated_at=timestamp,#type: ignore
    )

    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError as exc:
        db.session.rollback()
        raise AuthError(
            "EMAIL_ALREADY_EXISTS",
            "An account with this email already exists",
            409,
        ) from exc

    return {
        **user.to_public_dict(),
        "created_at": user.created_at,
    }

def check_password(*, email: object, passphrase: object) -> User:
    """
    This function check given crediental is correct
    And also check if the user account has reach the retried limit or is locked
    """
    
    normalized_email = normalize_email(email)
    if not normalized_email or not isinstance(passphrase, str):
        raise AuthError(
            "VALIDATION_ERROR", "Email and passphrase are required", 400
        )

    now = now_timestamp()
    max_attempts = int(current_app.config["AUTH_MAX_FAILED_ATTEMPTS"])
    lockout_seconds = int(current_app.config["AUTH_LOCKOUT_SECONDS"])
    
    user = db.session.scalar(select(User).where(User.email == normalized_email))
    if user is None:
        raise AuthError("ACCOUNT_NOT_FOUND", "Account does not exist", 404)

    if user.lock_until is not None and now < user.lock_until:
        raise AuthError(
            "ACCOUNT_LOCKED",
            "Account is temporarily locked",
            423,
            {"retry_after_seconds": user.lock_until - now},
        )

    # At the exact expiry second the previous lock no longer applies.
    if user.lock_until is not None and now >= user.lock_until:
        user.failed_attempts = 0
        user.lock_until = None

    try:
        password_valid = PASSWORD_HASHER.verify(user.password_hash, passphrase)
    except (VerifyMismatchError, InvalidHashError):
        password_valid = False

    if not password_valid:
        user.failed_attempts += 1
        user.updated_at = now

        if user.failed_attempts >= max_attempts:
            user.failed_attempts = max_attempts
            user.lock_until = now + lockout_seconds
            db.session.commit()
            raise AuthError(
                "ACCOUNT_LOCKED",
                "Account is temporarily locked",
                423,
                {"retry_after_seconds": lockout_seconds},
            )

        user.lock_until = None
        remaining_attempts = max_attempts - user.failed_attempts
        db.session.commit()
        raise AuthError(
            "INVALID_CREDENTIALS",
            "Passphrase is incorrect",
            401,
            {"remaining_attempts": remaining_attempts},
        )
        
    # Checking password need rehash if so then rehash
    if PASSWORD_HASHER.check_needs_rehash(user.password_hash):
        user.password_hash = PASSWORD_HASHER.hash(passphrase)
    
    return user

def login_user(*, user: User) -> LoginResult:
    """
    Login user by creating an AuthSession
    This function also clean up dead session
    """
    

    now = now_timestamp()
    token_ttl = int(current_app.config["AUTH_TOKEN_TTL_SECONDS"])
    
    user.failed_attempts = 0
    user.lock_until = None
    user.updated_at = now

    raw_token = secrets.token_urlsafe(32)
    expires_at = now + token_ttl
    db.session.add(
        AuthSession(
            token_hash=token_digest(raw_token),#type: ignore
            user=user,#type: ignore
            created_at=now,#type: ignore
            expires_at=expires_at,#type: ignore
            revoked_at=None,#type: ignore
        )
    )

    # Opportunistic cleanup prevents unbounded session-table growth.
    db.session.execute(
        delete(AuthSession).where(
            (AuthSession.expires_at <= now)
            | (AuthSession.revoked_at.is_not(None))
        )
    )
    db.session.commit()

    return LoginResult(
        token=raw_token,
        expires_at=expires_at,
        user=user.to_public_dict(),
    )


def authenticate_token(raw_token: str) -> AuthContext:
    """ 
    Check if the input token is a valid authenticate token
    """
    if not isinstance(raw_token, str) or not raw_token:
        raise AuthError("UNAUTHENTICATED", "Session token is invalid", 401)

    now = now_timestamp()
    digest = token_digest(raw_token)
    session = db.session.scalar(
        select(AuthSession).where(AuthSession.token_hash == digest)
    )

    if session is None or session.revoked_at is not None:
        raise AuthError("UNAUTHENTICATED", "Session token is invalid", 401)

    if now >= session.expires_at:
        db.session.delete(session)
        db.session.commit()
        raise AuthError(
            "SESSION_EXPIRED", "Session expired; log in again", 401
        )

    return AuthContext(
        user=session.user,
        token_hash=digest,
        expires_at=session.expires_at,
    )


def revoke_session(token_hash: str) -> None:
    """
        Delete/revoke user session. If session does not exist then this does nothing (only query if session exist)
    """
    
    session = db.session.scalar(
        select(AuthSession).where(AuthSession.token_hash == token_hash)
    )
    if session is None:
        return
    session.revoked_at = now_timestamp()
    db.session.commit()
