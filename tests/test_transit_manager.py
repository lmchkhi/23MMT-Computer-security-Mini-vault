# tests/test_transit_manager.py
import pytest
import os
from flask import Flask
from src.app import db
from src.core.vault import MiniVaultCore
from src.transit.manager import TransitKeyManager
from src.storage.kv.models import NamedKey

@pytest.fixture
def app_env():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def transit_manager(app_env):
    core = MiniVaultCore()
    core.state_file = "data/test_transit_vault.json"
    if os.path.exists(core.state_file):
        os.remove(core.state_file)
        
    core.init_vault("MasterPass123!")
    core.unlock_vault("MasterPass123!")
    
    manager = TransitKeyManager(core)
    yield manager
    
    if os.path.exists(core.state_file):
        os.remove(core.state_file)

def test_create_and_list_keys_no_secret_leaked(transit_manager):
    """Tiêu chí Nghiệm thu: API không bao giờ làm lộ vật liệu khóa thực"""
    owner = "alice@example.com"
    key_name = "my-test-key"
    
    # 1. Tạo khóa
    res = transit_manager.create_key(key_name, owner)
    assert res["key_name"] == key_name
    assert "encrypted_key_material_b64" not in res  # Không lộ bản mã
    assert "raw_aes_key" not in res                 # Không lộ bản rõ
    
    # 2. List khóa
    keys = transit_manager.list_keys(owner)
    assert len(keys) == 1
    assert keys[0]["key_name"] == key_name
    assert "encrypted_key_material_b64" not in keys[0]
    
    # 3. Kiểm tra DB có thực sự mã hóa không (Encrypted-at-Rest)
    db_key = NamedKey.query.filter_by(key_name=key_name).first()
    assert db_key is not None
    assert len(db_key.encrypted_key_material_b64) > 0

def test_prevent_duplicate_key(transit_manager):
    """Xử lý lỗi: Không cho phép tạo khóa trùng tên"""
    transit_manager.create_key("dup-key", "alice@example.com")
    with pytest.raises(ValueError, match="đã tồn tại"):
        transit_manager.create_key("dup-key", "alice@example.com")

def test_transit_vault_locked(transit_manager):
    """Xử lý lỗi: Không thể tạo khóa khi Vault bị khóa"""
    transit_manager.core.is_locked = True
    with pytest.raises(ValueError, match="VAULT_LOCKED"):
        transit_manager.create_key("any-key", "alice@example.com")