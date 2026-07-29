from __future__ import annotations

import base64

from tests.conftest import login_api, register_api


def _encrypt(client, headers, key_name: str, payload: bytes):
    return client.post(
        "/api/transit/encrypt",
        headers=headers,
        json={
            "key_name": key_name,
            "plaintext_b64": base64.b64encode(payload).decode("ascii"),
        },
    )


def test_encrypt_decrypt_round_trip_for_text_json_and_binary(
    client, alice_headers, seed_named_key
):
    seed_named_key(key_name="my-key")
    payloads = [
        b"hello mini vault",
        b'{"role":"student","active":true}',
        bytes(range(256)),
    ]

    for payload in payloads:
        encrypted = _encrypt(client, alice_headers, "my-key", payload)
        assert encrypted.status_code == 200
        body = encrypted.get_json()
        assert body["key_name"] == "my-key"
        assert body["ciphertext"].startswith("vault:my-key:")
        assert "key_material" not in str(body).lower()

        decrypted = client.post(
            "/api/transit/decrypt",
            headers=alice_headers,
            json={"ciphertext": body["ciphertext"]},
        )
        assert decrypted.status_code == 200
        assert base64.b64decode(decrypted.get_json()["plaintext_b64"]) == payload


def test_single_byte_tamper_is_rejected(
    client, alice_headers, seed_named_key
):
    seed_named_key(key_name="my-key")
    encrypted = _encrypt(client, alice_headers, "my-key", b"do not modify")
    ciphertext = encrypted.get_json()["ciphertext"]
    prefix, key_name, encoded = ciphertext.split(":", 2)
    raw = bytearray(base64.b64decode(encoded))
    raw[13] ^= 0x01
    tampered = f"{prefix}:{key_name}:{base64.b64encode(raw).decode('ascii')}"

    response = client.post(
        "/api/transit/decrypt",
        headers=alice_headers,
        json={"ciphertext": tampered},
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "CIPHERTEXT_INTEGRITY_ERROR"


def test_malformed_and_truncated_ciphertext_are_rejected(
    client, alice_headers, seed_named_key
):
    seed_named_key(key_name="my-key")
    malformed = [
        "not-vault-data",
        "vault:my-key:not-base64!",
        "vault:my-key:" + base64.b64encode(b"short").decode("ascii"),
    ]
    for value in malformed:
        response = client.post(
            "/api/transit/decrypt",
            headers=alice_headers,
            json={"ciphertext": value},
        )
        assert response.status_code == 400
        assert response.get_json()["error"]["code"] == "MALFORMED_CIPHERTEXT"


def test_wrong_key_usage_is_rejected(client, alice_headers, seed_named_key):
    seed_named_key(key_name="signing-key", key_usage="SIGN_VERIFY")
    response = _encrypt(client, alice_headers, "signing-key", b"message")
    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == "INVALID_KEY_USAGE"


def test_another_user_cannot_use_alices_named_key(
    client, strong_passphrase, seed_named_key
):
    seed_named_key(owner_email="alice@example.com", key_name="shared-name")
    assert register_api(client, "bob@example.com", strong_passphrase).status_code == 201
    bob_token = login_api(client, "bob@example.com", strong_passphrase)

    response = _encrypt(
        client,
        {"Authorization": f"Bearer {bob_token}"},
        "shared-name",
        b"attempt",
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "KEY_NOT_FOUND_OR_DENIED"


def test_locked_vault_refuses_encrypt(
    client, app, alice_headers, seed_named_key
):
    seed_named_key(key_name="my-key")
    app.config["TEST_VAULT_DEK"] = None

    response = _encrypt(client, alice_headers, "my-key", b"payload")
    assert response.status_code == 423
    assert response.get_json()["error"]["code"] == "VAULT_LOCKED"


def test_invalid_or_missing_session_never_reaches_transit(client):
    response = client.post(
        "/api/transit/encrypt",
        json={"key_name": "my-key", "plaintext_b64": "aGVsbG8="},
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "UNAUTHENTICATED"
