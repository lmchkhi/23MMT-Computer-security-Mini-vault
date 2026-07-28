from __future__ import annotations

from tests.conftest import register_api
from flask_sqlalchemy import record_queries

def test_login_and_register_pages_render(client):
    login = client.get("/login")
    register = client.get("/register")
    assert login.status_code == 200
    assert b"<h4 class=\"text-dark mb-4\">Welcome Back!</h4>" in login.data
    assert register.status_code == 200
    assert b"Create an Account!" in register.data


def test_web_registration_login_account_and_logout(
    client, strong_passphrase, app
):
    registered = client.post(
        "/register",
        data={
            "email": "alice@example.com",
            "passphrase": strong_passphrase,
            "confirm_passphrase": strong_passphrase,
        },
        follow_redirects=True,
    )
    assert registered.status_code == 200
    print(registered.data.decode())
    with app.app_context():
        print(record_queries.get_recorded_queries())
    assert b"Account created" in registered.data

    logged_in = client.post(
        "/login",
        data={"email": "alice@example.com", "passphrase": strong_passphrase},
        follow_redirects=False,
    )
    assert logged_in.status_code == 302
    cookie = logged_in.headers.get("Set-Cookie", "")
    assert "mini_vault_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie

    # Temporary remove getting user info as currently there is no /account route
    # account = client.get("/account")
    # assert account.status_code == 200
    # assert b"alice@example.com" in account.data
    # assert b"0.2 is ready" in account.data

    logged_out = client.get("/logout", data={}, follow_redirects=True)
    assert logged_out.status_code == 200
    assert b"You have been logged out" in logged_out.data


def test_web_lockout_displays_countdown(client, strong_passphrase):
    assert register_api(client, "alice@example.com", strong_passphrase).status_code == 201

    for _ in range(4):
        response = client.post(
            "/login",
            data={"email": "alice@example.com", "passphrase": "Wrong-Passphrase-1!"},
        )
        assert response.status_code == 200

    fifth = client.post(
        "/login",
        data={"email": "alice@example.com", "passphrase": "Wrong-Passphrase-1!"},
    )
    assert fifth.status_code == 200
    
    flash_mess = f"You have enter the passpharse wrong 5 time, please wait for 300 seconds to login again".encode()
    assert flash_mess in fifth.data

def test_account_redirects_without_browser_session(client):
    response = client.get("/index", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
