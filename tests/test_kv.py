import pytest
import os
from flask import Flask
from src.app import db
from src.core.vault import MiniVaultCore
from src.kv.engine import KVEngine
from src.storage.kv.models import KVSecret

@pytest.fixture
def app_env():
    """Thiết lập môi trường Flask ảo và Database trên RAM cho việc test"""
    app = Flask(__name__)
    # Sử dụng SQLite in-memory để test nhanh, không tạo file vật lý
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    with app.app_context():
        db.create_all() # Tạo các bảng trong RAM
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def kv_engine(app_env):
    """Thiết lập Vault Core (đã mở khóa) và KV Engine"""
    core = MiniVaultCore()
    core.state_file = "data/test_vault_state.json"
    
    # Dọn dẹp file test cũ nếu có
    if os.path.exists(core.state_file):
        os.remove(core.state_file)
        
    # Khởi tạo và mở khóa để có DEK
    core.init_vault("MatKhauTest123!")
    core.unlock_vault("MatKhauTest123!")
    
    engine = KVEngine(core)
    yield engine
    
    # Dọn dẹp sau khi test
    if os.path.exists(core.state_file):
        os.remove(core.state_file)

def test_kv_round_trip(kv_engine):
    """Tiêu chí nghiệm thu 1: Ghi sau đó đọc phải trả về chính xác dữ liệu gốc (round-trip test)"""
    test_path = "secret/alice@example.com/db"
    test_data = {"username": "admin", "password": "super_secret_password"}
    
    # Thực hiện Ghi
    kv_engine.write(test_path, test_data, token="dummy_token")
    
    # Thực hiện Đọc
    retrieved_data = kv_engine.read(test_path, token="dummy_token")
    
    # Kiểm tra
    assert retrieved_data == test_data, "Dữ liệu giải mã không khớp với dữ liệu gốc!"

def test_kv_tamper_detection(kv_engine):
    """Tiêu chí nghiệm thu 2: Thay đổi thủ công 1 byte bản mã -> read phải từ chối"""
    test_path = "secret/bob@example.com/api"
    test_data = {"api_key": "123456789"}
    
    kv_engine.write(test_path, test_data, token="dummy_token")
    
    # Can thiệp vào Database để sửa bản mã (Giả mạo dữ liệu)
    secret = KVSecret.query.filter_by(path=test_path).first()
    
    # Lấy bản mã b64 hiện tại, đổi ký tự cuối cùng để làm hỏng dữ liệu
    tampered_ciphertext = secret.ciphertext_b64[:-1] + ("A" if secret.ciphertext_b64[-1] != "A" else "B") #type:ignore
    secret.ciphertext_b64 = tampered_ciphertext #type:ignore
    db.session.commit()
    
    # Lệnh read bắt buộc phải phát hiện ra (Tag không khớp) và văng lỗi
    with pytest.raises(ValueError, match="Lỗi: Dữ liệu đã bị giả mạo hoặc Tag xác thực không khớp."):
        kv_engine.read(test_path, token="dummy_token")

def test_kv_vault_locked(kv_engine):
    """Kiểm tra xử lý lỗi khi Vault bị khóa"""
    # Ép Vault vào trạng thái khóa
    kv_engine.core.is_locked = True
    
    with pytest.raises(ValueError, match="VAULT_LOCKED"):
        kv_engine.write("some/path", {"data": "123"}, token="dummy")