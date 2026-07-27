from __future__ import annotations

import os

import pytest

from src.app import create_app
from src.extensions import db
from src.transit.key_store import wrap_key_material
from src.transit.models import TransitNamedKey


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
            "TRANSIT_CLOCK": lambda: clock["now"],
            "AUTH_COOKIE_SECURE": False,
            "TEST_VAULT_DEK": b"D" * 32,
            "ENABLE_TRANSIT_DEMO_KEY": True,
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


def login_api(client, email: str, passphrase: str) -> str:
    response = client.post(
        "/api/auth/login",
        json={"email": email, "passphrase": passphrase},
    )
    assert response.status_code == 200
    return response.get_json()["token"]


@pytest.fixture()
def registered_user(client, strong_passphrase):
    response = register_api(client, "alice@example.com", strong_passphrase)
    assert response.status_code == 201
    return {"email": "alice@example.com", "passphrase": strong_passphrase}


@pytest.fixture()
def alice_token(client, registered_user):
    return login_api(
        client, registered_user["email"], registered_user["passphrase"]
    )


@pytest.fixture()
def alice_headers(alice_token):
    return {"Authorization": f"Bearer {alice_token}"}


@pytest.fixture()
def seed_named_key(app, clock):
    def seed(
        *,
        owner_email: str = "alice@example.com",
        key_name: str = "my-key",
        key_usage: str = "ENCRYPT_DECRYPT",
        key_material: bytes | None = None,
    ) -> TransitNamedKey:
        material = key_material or os.urandom(32)
        with app.app_context():
            record = TransitNamedKey(
                owner_email=owner_email,
                key_name=key_name,
                key_usage=key_usage,
                encrypted_key_material_b64=wrap_key_material(
                    owner_email=owner_email,
                    key_name=key_name,
                    key_usage=key_usage,
                    key_material=material,
                ),
                created_at=clock["now"],
                updated_at=clock["now"],
                revoked_at=None,
            )
            db.session.add(record)
            db.session.commit()
            record_id = record.id
        return record_id

    return seed
