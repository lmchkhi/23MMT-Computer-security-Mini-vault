import json
import os
import base64
import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage.models import KVSecret
from src.storage.db import db

class KVEngine:
    def __init__(self, core_vault):
        """Nhận vào instance của MiniVaultCore để lấy DEK và trạng thái khóa"""
        self.core = core_vault

    def write(self, path: str, data: dict, token: str) -> dict:
        """Mã hóa payload JSON và ghi xuống cơ sở dữ liệu"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")
            
        # Lưu ý: Phần kiểm tra token thuộc Task 1.2, sẽ được nhóm bổ sung sau.
            
        # 1. Chuyển JSON thành bytes và tạo Nonce (12 bytes cho GCM)
        payload_bytes = json.dumps(data).encode('utf-8')
        nonce = os.urandom(12)
        
        # 2. Mã hóa bằng DEK
        aesgcm = AESGCM(self.core.dek)
        encrypted_data = aesgcm.encrypt(nonce, payload_bytes, associated_data=None)
        
        # Thư viện cryptography tự động nối tag (16 bytes) vào cuối ciphertext.
        # Chúng ta cần tách ra để lưu đúng theo Data Contract.
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]
        
        # 3. Mã hóa sang Base64
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        tag_b64 = base64.b64encode(tag).decode('utf-8')
        
        # 4. Ghi đè hoặc Tạo mới trong Database
        secret = KVSecret.query.filter_by(path=path).first()
        time_now = datetime.datetime.now()
        if secret:
            secret.nonce_b64 = nonce_b64
            secret.ciphertext_b64 = ciphertext_b64
            secret.tag_b64 = tag_b64
            
        else:
            secret = KVSecret(
                path=path, #type: ignore
                nonce_b64=nonce_b64, #type: ignore
                ciphertext_b64=ciphertext_b64, #type: ignore
                tag_b64=tag_b64 #type: ignore
            )
            db.session.add(secret)
            
        db.session.commit()
        return {"time_of_op":time_now}

    def read(self, path: str, token: str) -> dict:
        """Đọc và giải mã dữ liệu từ cơ sở dữ liệu"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")
            
        # 1. Truy vấn DB
        secret = KVSecret.query.filter_by(path=path).first()
        if not secret:
            raise ValueError("NOT_FOUND")
            
        # 2. Giải mã Base64
        nonce = base64.b64decode(secret.nonce_b64)
        ciphertext = base64.b64decode(secret.ciphertext_b64)
        tag = base64.b64decode(secret.tag_b64)
        
        # 3. Nối ciphertext và tag lại để thư viện xử lý
        encrypted_data = ciphertext + tag
        aesgcm = AESGCM(self.core.dek)
        
        try:
            # Nếu bản mã hoặc tag bị thay đổi, dòng này sẽ quăng lỗi
            decrypted_bytes = aesgcm.decrypt(nonce, encrypted_data, associated_data=None)
            return json.loads(decrypted_bytes.decode('utf-8'))
        except Exception:
            raise ValueError("Lỗi: Dữ liệu đã bị giả mạo hoặc Tag xác thực không khớp.")

    def delete(self, path: str, token: str) -> dict:
        """Xóa vĩnh viễn bản ghi khỏi cơ sở dữ liệu"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")
            
        secret = KVSecret.query.filter_by(path=path).first()
        if secret:
            db.session.delete(secret)
            db.session.commit()
            
        return {"status": "deletion confirmation"}
    
