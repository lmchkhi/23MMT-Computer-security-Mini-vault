# tests/test_core.py
import pytest
import os
from src.core.vault import MiniVaultCore

TEST_DATA_FILE = "data/test_vault_state.json"

@pytest.fixture
def vault():
    """Fixture này sẽ tạo một môi trường test sạch sẽ trước mỗi hàm test"""
    v = MiniVaultCore()
    # Chuyển đường dẫn lưu file sang file test để không đè dữ liệu thật
    v.state_file = TEST_DATA_FILE 
    
    # Dọn dẹp file test cũ (nếu có) trước khi chạy
    if os.path.exists(TEST_DATA_FILE):
        os.remove(TEST_DATA_FILE)
        
    yield v  # Trả đối tượng vault về cho hàm test sử dụng
    
    # Dọn dẹp file test sau khi chạy xong để giữ thư mục sạch sẽ
    if os.path.exists(TEST_DATA_FILE):
        os.remove(TEST_DATA_FILE)

def test_vault_init_and_unlock(vault):
    """Kịch bản kiểm thử: Khởi tạo, nhập sai mật khẩu, và nhập đúng mật khẩu"""
    
    # 1. Test quá trình Khởi tạo (Init)
    vault.init_vault("MatKhauSieuKho123!")
    assert os.path.exists(TEST_DATA_FILE) == True, "Lỗi: Không tạo được file trạng thái"
    
    # 2. Test Mở khóa với mật khẩu SAI
    # Pytest sẽ kiểm tra xem hàm có chủ động quăng lỗi ValueError hay không
    with pytest.raises(ValueError, match="Lỗi: Không thể mở khóa Vault"):
        vault.unlock_vault("MatKhauSai")
        
    # 3. Test Mở khóa với mật khẩu ĐÚNG
    vault.unlock_vault("MatKhauSieuKho123!")
    assert vault.is_locked == False, "Lỗi: Trạng thái không chuyển sang Unlock"
    assert vault.dek is not None, "Lỗi: Không giải mã được DEK vào bộ nhớ"