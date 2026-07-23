import json
import os

def save_vault_state(file_path: str, data: dict):
    """Ghi dữ liệu cấu hình/trạng thái của Vault ra file JSON"""
    # Đảm bảo thư mục chứa file đã tồn tại
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def load_vault_state(file_path: str) -> dict:
    """Đọc dữ liệu từ file JSON, trả về None nếu file chưa tồn tại"""
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)