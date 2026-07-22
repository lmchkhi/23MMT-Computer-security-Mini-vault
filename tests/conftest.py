from __future__ import annotations

import pytest

from src.app import create_app


@pytest.fixture()
def clock():
    return {"now": 1_700_000_000}


@pytest.fixture()
def app(tmp_path, clock):
    application = create_app(
        {
            "TESTING": True,
            "AUTH_DATABASE": str(tmp_path / "test.db"),
            "AUTH_CLOCK": lambda: clock["now"],
        }
    )
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def strong_passphrase():
    return "Correct-Horse-9!"


def register(client, email: str, passphrase: str):
    return client.post(
        "/api/auth/register",
        json={
            "email": email,
            "passphrase": passphrase,
            "confirm_passphrase": passphrase,
        },
    )


@pytest.fixture()
def registered_user(client, strong_passphrase):
    response = register(client, "alice@example.com", strong_passphrase)
    assert response.status_code == 201
    return {"email": "alice@example.com", "passphrase": strong_passphrase}
