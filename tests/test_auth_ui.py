from __future__ import annotations

from tests.conftest import register_api


def test_login_and_register_pages_render(client):
    login = client.get("/auth/login")
    register = client.get("/auth/register")
    assert login.status_code == 200
    assert b"Log in to your vault" in login.data
    assert register.status_code == 200
    assert b"Create an account" in register.data


def test_web_registration_login_account_and_logout(
    client, strong_passphrase
):
    registered = client.post(
        "/auth/register",
        data={
            "email": "alice@example.com",
            "passphrase": strong_passphrase,
            "confirm_passphrase": strong_passphrase,
        },
        follow_redirects=True,
    )
    assert registered.status_code == 200
    assert b"Account created" in registered.data

    logged_in = client.post(
        "/auth/login",
        data={"email": "alice@example.com", "passphrase": strong_passphrase},
        follow_redirects=False,
    )
    assert logged_in.status_code == 302
    cookie = logged_in.headers.get("Set-Cookie", "")
    assert "mini_vault_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie

    account = client.get("/auth/account")
    assert account.status_code == 200
    assert b"alice@example.com" in account.data
    assert b"Authenticated workspace" in account.data

    logged_out = client.post("/auth/logout", data={}, follow_redirects=True)
    assert logged_out.status_code == 200
    assert b"You have been logged out" in logged_out.data


def test_web_lockout_displays_countdown(client, strong_passphrase):
    assert register_api(client, "alice@example.com", strong_passphrase).status_code == 201

    for _ in range(4):
        response = client.post(
            "/auth/login",
            data={"email": "alice@example.com", "passphrase": "Wrong-Passphrase-1!"},
        )
        assert response.status_code == 200

    fifth = client.post(
        "/auth/login",
        data={"email": "alice@example.com", "passphrase": "Wrong-Passphrase-1!"},
    )
    assert fifth.status_code == 200
    assert b'data-lockout-seconds="300"' in fifth.data
    assert b"temporarily locked" in fifth.data


def test_account_redirects_without_browser_session(client):
    response = client.get("/auth/account", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]
