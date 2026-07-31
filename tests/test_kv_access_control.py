from __future__ import annotations

import logging

import pytest

from src.kv.utils.access_control import authorize_secret_path, parse_secret_path
from src.kv.utils.errors import KvAccessError


def test_owner_path_is_authorized_and_normalized(app):
    with app.app_context():
        result = authorize_secret_path(
            "secret/Alice@Example.COM/database/password",
            "alice@example.com",
        )
    assert result.path == "secret/alice@example.com/database/password"
    assert result.relative_path == "database/password"


def test_cross_user_path_is_always_denied_and_logged(app, caplog):
    with app.app_context(), caplog.at_level(logging.WARNING):
        with pytest.raises(KvAccessError) as raised:
            authorize_secret_path(
                "secret/bob@example.com/database/password",
                "alice@example.com",
            )

    assert raised.value.code == "PERMISSION_DENIED"
    assert raised.value.status_code == 403
    assert "KV_ACCESS_DENIED" in caplog.text
    assert "alice@example.com" in caplog.text
    assert "bob@example.com" in caplog.text


def test_path_traversal_and_malformed_namespaces_are_rejected(app):
    bad_paths = [
        "secret/alice@example.com/../bob",
        "secret/alice@example.com/",
        "/secret/alice@example.com/db",
        "public/alice@example.com/db",
        "secret/alice@example.com//db",
    ]
    with app.app_context():
        for path in bad_paths:
            with pytest.raises(KvAccessError) as raised:
                parse_secret_path(path)
            assert raised.value.code == "INVALID_PATH"


def test_api_allows_owner_and_denies_other_user(client, alice_headers):
    own = client.post(
        "/api/kv/access/check",
        headers=alice_headers,
        json={"path": "secret/alice@example.com/db"},
    )
    assert own.status_code == 200
    assert own.get_json()["authorized"] is True

    denied = client.post(
        "/api/kv/access/check",
        headers=alice_headers,
        json={"path": "secret/bob@example.com/db"},
    )
    assert denied.status_code == 403
    assert denied.get_json()["error"]["code"] == "PERMISSION_DENIED"


def test_missing_token_is_rejected_before_path_authorization(client):
    response = client.post(
        "/api/kv/access/check",
        json={"path": "secret/bob@example.com/db"},
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHENTICATED"


def test_kv_ownership_ui_requires_login_and_renders_for_owner(
    client, registered_user
):
    anonymous = client.get("/kv/access-control/", follow_redirects=False)
    assert anonymous.status_code == 302
    assert "/auth/login" in anonymous.headers["Location"]

    logged_in = client.post(
        "/auth/login",
        data={
            "email": registered_user["email"],
            "passphrase": registered_user["passphrase"],
        },
        follow_redirects=False,
    )
    assert logged_in.status_code == 302

    page = client.get("/kv/access-control/")
    assert page.status_code == 200
    assert b"Ownership before storage" in page.data
    assert b"secret/alice@example.com/db" in page.data
