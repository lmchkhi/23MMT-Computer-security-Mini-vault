import os
import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage.models import NamedKey
from src.storage.db import db
from src.core import kv_obj
class TransitKeyManager:
    allowed_key_type = (
        'ENCRYPT_DECRYPT',
    )
    def __init__(self, core_vault):
        """Nhận vào instance của MiniVaultCore để lấy DEK và trạng thái khóa"""
        self.core = core_vault

    def create_key(self, key_name: str, owner_email: str, key_usage="ENCRYPT_DECRYPT") -> dict:
        """Tạo khóa AES-256 mới và mã hóa nó bằng DEK trước khi lưu xuống DB"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")
        if key_usage not in self.allowed_key_type:
            raise ValueError("Wrong key usage")
        # Kiểm tra khóa đã tồn tại chưa
        existing_key = NamedKey.query.filter_by(key_name=key_name).first()
        if existing_key:
            raise ValueError(f"Lỗi: Key '{key_name}' đã tồn tại!")

        # 1. Sinh ngẫu nhiên khóa AES-256 (32 bytes) cho Client
        raw_aes_key = secrets.token_bytes(32)

        # 2. Mã hóa khóa AES đó bằng DEK hiện hành trong bộ nhớ (AES-256-GCM)
        aesgcm = AESGCM(self.core.dek)
        nonce = os.urandom(12)
        encrypted_key = aesgcm.encrypt(nonce, raw_aes_key, associated_data=bytes(owner_email, 'ascii'))

        # Trộn nonce (12 bytes) + encrypted_key (chứa sẵn tag) và chuyển sang Base64
        combined_encrypted_key = nonce + encrypted_key
        encrypted_key_material_b64 = base64.b64encode(combined_encrypted_key).decode('utf-8')

        # 3. Lưu xuống Database theo đúng Data Contract
        new_key = NamedKey(
            key_name=key_name,
            owner_email=owner_email,
            key_usage=key_usage,
            encrypted_key_material_b64=encrypted_key_material_b64
        )
        db.session.add(new_key)
        db.session.commit()

        # TUYỆT ĐỐI KHÔNG TRẢ VỀ RAW KEY
        return {
            "key_name": new_key.key_name,
            "owner_email": new_key.owner_email,
            "key_usage": new_key.key_usage,
            "status": "created"
        }

    def list_keys(self, owner_email: str) -> list:
        """Liệt kê danh sách tên khóa và key_usage thuộc sở hữu của user"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")

        keys = NamedKey.query.filter_by(owner_email=owner_email).all()
        
        # Chỉ trả về metadata, không bao giờ trả về key material
        return [
            {
                "key_name": k.key_name,
                "owner_email": k.owner_email,
                "key_usage": k.key_usage
            }
            for k in keys
        ]

    def revoke_key(self, key_name: str, owner_email: str) -> dict:
        """Xóa vĩnh viễn một khóa định danh"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")

        key = NamedKey.query.filter_by(key_name=key_name, owner_email=owner_email).first()
        if not key:
            raise ValueError("NOT_FOUND_OR_PERMISSION_DENIED")

        db.session.delete(key)
        db.session.commit()

        return {"status": "revoked", "key_name": key_name}
    
transit_key_obj = TransitKeyManager(kv_obj)