import os

import pytest
from flask import Flask, g

from src.app import db
from src.core.vault import MiniVaultCore
from src.kv.utils.engine import KVEngine
from src.storage import AuthSession, User
from src.storage.kv.models import KVSecret


@pytest.fixture
def app_env():
    """Create an in-memory Flask/SQLAlchemy environment for KV unit tests."""

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def kv_auth_context(app_env):
    """Supply the authenticated request context now required by Feature 0.2."""

    request_context = app_env.test_request_context()
    request_context.push()
    user = User(
        email="alice@example.com",
        password_hash="test-only-hash",
        failed_attempts=0,
        lock_until=None,
        created_at=1_700_000_000,
        updated_at=1_700_000_000,
    )
    db.session.add(user)
    db.session.flush()
    db.session.add(
        AuthSession(
            token_hash="dummy_token",
            user=user,
            created_at=1_700_000_000,
            expires_at=1_700_001_800,
            revoked_at=None,
        )
    )
    db.session.commit()
    g.auth_user = user
    try:
        yield
    finally:
        request_context.pop()


@pytest.fixture
def kv_engine(app_env, kv_auth_context):
    core = MiniVaultCore()
    core.state_file = "data/test_vault_state.json"
    if os.path.exists(core.state_file):
        os.remove(core.state_file)

    core.init_vault("MatKhauTest123!")
    core.unlock_vault("MatKhauTest123!")
    engine = KVEngine(core)
    yield engine

    if os.path.exists(core.state_file):
        os.remove(core.state_file)


def test_kv_round_trip(kv_engine):
    test_path = "secret/alice@example.com/db"
    test_data = {"username": "admin", "password": "super_secret_password"}

    kv_engine.write(test_path, test_data, token="dummy_token")
    retrieved_data = kv_engine.read(test_path, token="dummy_token")
    assert retrieved_data == test_data


def test_kv_tamper_detection(kv_engine):
    test_path = "secret/alice@example.com/api"
    test_data = {"api_key": "123456789"}
    kv_engine.write(test_path, test_data, token="dummy_token")

    secret = KVSecret.query.filter_by(path=test_path).first()
    assert secret is not None
    secret.ciphertext_b64 = secret.ciphertext_b64[:-1] + (
        "A" if secret.ciphertext_b64[-1] != "A" else "B"
    )
    db.session.commit()

    with pytest.raises(
        ValueError,
        match="Lỗi: Dữ liệu đã bị giả mạo hoặc Tag xác thực không khớp.",
    ):
        kv_engine.read(test_path, token="dummy_token")


def test_kv_vault_locked(kv_engine):
    kv_engine.core.is_locked = True
    with pytest.raises(ValueError, match="VAULT_LOCKED"):
        kv_engine.write("some/path", {"data": "123"}, token="dummy")
