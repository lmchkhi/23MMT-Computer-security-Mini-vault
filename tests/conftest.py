from __future__ import annotations

import pytest

from src.app import create_app
from src.extensions import db


@pytest.fixture()
def clock():
    return {"now": 1_700_000_000}


@pytest.fixture()
def app(tmp_path, clock):
    database = tmp_path / "test.db"
    application = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database.as_posix()}",
            "AUTH_CLOCK": lambda: clock["now"],
            "AUTH_COOKIE_SECURE": False,
        }
    )
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def strong_passphrase():
    return "Correct-Horse-9!"


def register_api(client, email: str, passphrase: str):
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
    response = register_api(client, "alice@example.com", strong_passphrase)
    assert response.status_code == 201
    return {"email": "alice@example.com", "passphrase": strong_passphrase}
