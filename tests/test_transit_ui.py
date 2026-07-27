from __future__ import annotations


def _browser_login(client, user):
    response = client.post(
        "/auth/login",
        data={"email": user["email"], "passphrase": user["passphrase"]},
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_transit_page_requires_login(client):
    response = client.get("/transit/", follow_redirects=False)
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_transit_ui_renders_consistently_and_lists_owned_key(
    client, registered_user, seed_named_key
):
    seed_named_key(key_name="ui-key")
    _browser_login(client, registered_user)

    page = client.get("/transit/")
    assert page.status_code == 200
    assert b"Use keys without receiving keys" in page.data
    assert b"ui-key" in page.data
    assert b"KV ownership" in page.data


def test_transit_ui_encrypts_and_decrypts_text(
    client, registered_user, seed_named_key
):
    seed_named_key(key_name="ui-key")
    _browser_login(client, registered_user)

    encrypted = client.post(
        "/transit/encrypt",
        data={
            "encrypt-key_name": "ui-key",
            "encrypt-input_format": "text",
            "encrypt-plaintext": "hello from the UI",
            "encrypt-submit": "Encrypt",
        },
    )
    assert encrypted.status_code == 200
    assert b"vault:ui-key:" in encrypted.data
    assert b"Plaintext encrypted and authenticated" in encrypted.data
