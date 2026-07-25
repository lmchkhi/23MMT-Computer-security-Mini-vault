from __future__ import annotations

from sqlalchemy import select

from src.storage import User
from src.app import db
from tests.conftest import register_api


def login(client, email: str, passphrase: str):
    return client.post(
        "/api/auth/login", json={"email": email, "passphrase": passphrase}
    )


def test_register_hashes_password_and_normalizes_email(
    client, app, strong_passphrase
):
    response = register_api(client, "  Alice@Example.COM ", strong_passphrase)
    assert response.status_code == 201
    assert response.get_json()["user"]["email"] == "alice@example.com"

    with app.app_context():
        user = db.session.scalar(select(User))
        assert user is not None
        assert user.password_hash != strong_passphrase
        assert user.password_hash.startswith("$argon2id$")


def test_registration_rejects_weak_or_mismatched_passphrase(client):
    response = client.post(
        "/api/auth/register",
        json={
            "email": "alice@example.com",
            "passphrase": "weak",
            "confirm_passphrase": "different",
        },
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_duplicate_email_is_rejected_case_insensitively(
    client, strong_passphrase
):
    assert register_api(client, "alice@example.com", strong_passphrase).status_code == 201
    response = register_api(client, "ALICE@example.com", strong_passphrase)
    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == "EMAIL_ALREADY_EXISTS"


def test_login_returns_30_minute_opaque_session_token(
    client, registered_user, clock
):
    response = login(client, registered_user["email"], registered_user["passphrase"])
    body = response.get_json()
    assert response.status_code == 200
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 1800
    assert body["expires_at"] == clock["now"] + 1800
    assert len(body["token"]) >= 32


def test_five_consecutive_failures_lock_for_exactly_five_minutes(
    client, registered_user, clock
):
    for attempt in range(1, 5):
        response = login(client, registered_user["email"], "Wrong-Passphrase-1!")
        assert response.status_code == 401
        assert response.get_json()["error"]["details"]["remaining_attempts"] == 5 - attempt

    fifth = login(client, registered_user["email"], "Wrong-Passphrase-1!")
    assert fifth.status_code == 423
    assert fifth.get_json()["error"]["details"]["retry_after_seconds"] == 300

    locked = login(client, registered_user["email"], registered_user["passphrase"])
    assert locked.status_code == 423

    clock["now"] += 299
    almost = login(client, registered_user["email"], registered_user["passphrase"])
    assert almost.status_code == 423
    assert almost.get_json()["error"]["details"]["retry_after_seconds"] == 1

    clock["now"] += 1
    unlocked = login(client, registered_user["email"], registered_user["passphrase"])
    assert unlocked.status_code == 200


def test_protected_route_requires_valid_nonexpired_token(
    client, registered_user, clock
):
    missing = client.get("/api/auth/me")
    assert missing.status_code == 401

    token = login(
        client, registered_user["email"], registered_user["passphrase"]
    ).get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    accepted = client.get("/api/auth/me", headers=headers)
    assert accepted.status_code == 200
    assert accepted.get_json()["user"]["email"] == registered_user["email"]

    clock["now"] += 1800
    expired = client.get("/api/auth/me", headers=headers)
    assert expired.status_code == 401
    assert expired.get_json()["error"]["code"] == "SESSION_EXPIRED"


def test_logout_revokes_session(client, registered_user):
    token = login(
        client, registered_user["email"], registered_user["passphrase"]
    ).get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHENTICATED"


def test_unknown_account_returns_required_error(client, strong_passphrase):
    response = login(client, "nobody@example.com", strong_passphrase)
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "ACCOUNT_NOT_FOUND"
