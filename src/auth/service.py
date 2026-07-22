from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import current_app

from .errors import AuthError
from .validation import normalize_email, validate_email, validate_passphrase

PASSWORD_HASHER = PasswordHasher()


@dataclass(frozen=True)
class LoginResult:
    token: str
    expires_at: int
    user: dict[str, object]


def now_timestamp() -> int:
    """Return UTC epoch seconds; tests may inject a deterministic clock."""
    clock = current_app.config.get("AUTH_CLOCK", time.time)
    return int(clock())


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def register_user(
    connection: sqlite3.Connection,
    *,
    email: object,
    passphrase: object,
    confirm_passphrase: object,
) -> dict[str, object]:
    normalized_email = normalize_email(email)

    field_errors: dict[str, list[str]] = {}
    email_errors = validate_email(normalized_email)
    password_errors = validate_passphrase(passphrase)

    if email_errors:
        field_errors["email"] = email_errors
    if password_errors:
        field_errors["passphrase"] = password_errors
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
    password_hash = PASSWORD_HASHER.hash(passphrase)

    try:
        cursor = connection.execute(
            """
            INSERT INTO auth_users (
                email, password_hash, failed_attempts, lock_until,
                created_at, updated_at
            ) VALUES (?, ?, 0, NULL, ?, ?)
            """,
            (normalized_email, password_hash, timestamp, timestamp),
        )
        connection.commit()
    except sqlite3.IntegrityError as exc:
        connection.rollback()
        raise AuthError(
            "EMAIL_ALREADY_EXISTS",
            "An account with this email already exists",
            409,
        ) from exc

    return {
        "id": cursor.lastrowid,
        "email": normalized_email,
        "created_at": timestamp,
    }


def login_user(
    connection: sqlite3.Connection,
    *,
    email: object,
    passphrase: object,
) -> LoginResult:
    normalized_email = normalize_email(email)
    if not normalized_email or not isinstance(passphrase, str):
        raise AuthError("VALIDATION_ERROR", "Email and passphrase are required", 400)

    now = now_timestamp()
    max_attempts = int(current_app.config["AUTH_MAX_FAILED_ATTEMPTS"])
    lockout_seconds = int(current_app.config["AUTH_LOCKOUT_SECONDS"])
    token_ttl = int(current_app.config["AUTH_TOKEN_TTL_SECONDS"])

    # IMMEDIATE serializes competing login attempts, preventing two requests from
    # bypassing the consecutive-failure counter.
    connection.execute("BEGIN IMMEDIATE")
    try:
        user = connection.execute(
            "SELECT * FROM auth_users WHERE email = ? COLLATE NOCASE",
            (normalized_email,),
        ).fetchone()

        if user is None:
            connection.rollback()
            raise AuthError("ACCOUNT_NOT_FOUND", "Account does not exist", 404)

        failed_attempts = int(user["failed_attempts"])
        lock_until = user["lock_until"]

        if lock_until is not None and now < int(lock_until):
            connection.rollback()
            raise AuthError(
                "ACCOUNT_LOCKED",
                "Account is temporarily locked",
                423,
                {"retry_after_seconds": int(lock_until) - now},
            )

        # The exact lock period has elapsed. Start a fresh failure sequence.
        if lock_until is not None and now >= int(lock_until):
            failed_attempts = 0
            connection.execute(
                "UPDATE auth_users SET failed_attempts = 0, lock_until = NULL, updated_at = ? WHERE id = ?",
                (now, user["id"]),
            )

        try:
            password_valid = PASSWORD_HASHER.verify(user["password_hash"], passphrase)
        except (VerifyMismatchError, InvalidHashError):
            password_valid = False

        if not password_valid:
            failed_attempts += 1

            if failed_attempts >= max_attempts:
                new_lock_until = now + lockout_seconds
                connection.execute(
                    """
                    UPDATE auth_users
                    SET failed_attempts = ?, lock_until = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (max_attempts, new_lock_until, now, user["id"]),
                )
                connection.commit()
                raise AuthError(
                    "ACCOUNT_LOCKED",
                    "Account is temporarily locked",
                    423,
                    {"retry_after_seconds": lockout_seconds},
                )

            connection.execute(
                """
                UPDATE auth_users
                SET failed_attempts = ?, lock_until = NULL, updated_at = ?
                WHERE id = ?
                """,
                (failed_attempts, now, user["id"]),
            )
            connection.commit()
            raise AuthError(
                "INVALID_CREDENTIALS",
                "Passphrase is incorrect",
                401,
                {"remaining_attempts": max_attempts - failed_attempts},
            )

        new_hash = user["password_hash"]
        if PASSWORD_HASHER.check_needs_rehash(user["password_hash"]):
            new_hash = PASSWORD_HASHER.hash(passphrase)

        connection.execute(
            """
            UPDATE auth_users
            SET password_hash = ?, failed_attempts = 0,
                lock_until = NULL, updated_at = ?
            WHERE id = ?
            """,
            (new_hash, now, user["id"]),
        )

        raw_token = secrets.token_urlsafe(32)
        expires_at = now + token_ttl
        connection.execute(
            """
            INSERT INTO auth_sessions (
                token_hash, user_id, created_at, expires_at, revoked_at
            ) VALUES (?, ?, ?, ?, NULL)
            """,
            (token_digest(raw_token), user["id"], now, expires_at),
        )

        # Opportunistic cleanup keeps the table from growing forever.
        connection.execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
            (now,),
        )
        connection.commit()
    except AuthError:
        raise
    except Exception:
        connection.rollback()
        raise

    return LoginResult(
        token=raw_token,
        expires_at=expires_at,
        user={"id": user["id"], "email": user["email"]},
    )


def authenticate_token(
    connection: sqlite3.Connection,
    raw_token: str,
) -> tuple[dict[str, object], str]:
    now = now_timestamp()
    digest = token_digest(raw_token)

    session = connection.execute(
        """
        SELECT
            s.token_hash, s.expires_at, s.revoked_at,
            u.id AS user_id, u.email
        FROM auth_sessions AS s
        JOIN auth_users AS u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (digest,),
    ).fetchone()

    if session is None or session["revoked_at"] is not None:
        raise AuthError("UNAUTHENTICATED", "Session token is invalid", 401)

    if now >= int(session["expires_at"]):
        connection.execute(
            "DELETE FROM auth_sessions WHERE token_hash = ?",
            (digest,),
        )
        connection.commit()
        raise AuthError("SESSION_EXPIRED", "Session expired; log in again", 401)

    return {"id": session["user_id"], "email": session["email"]}, digest


def revoke_session(connection: sqlite3.Connection, digest: str) -> None:
    connection.execute(
        "UPDATE auth_sessions SET revoked_at = ? WHERE token_hash = ?",
        (now_timestamp(), digest),
    )
    connection.commit()
