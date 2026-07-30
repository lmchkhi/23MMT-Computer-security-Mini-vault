import os
import secrets
import base64
import datetime
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from src.storage.kv.models import NamedKey
from .service import TransitError
from .misc import validate_key_name
from src.app import db
from src.core import vault_obj
class TransitKeyManager:
    allowed_key_type = (
        'ENCRYPT_DECRYPT',
        "SIGN_VERIFY"
    )
    def __init__(self, core_vault = None):
        """Nhận vào instance của MiniVaultCore để lấy DEK và trạng thái khóa"""
        if core_vault is None:
            core_vault = vault_obj
        self.core = core_vault

    def check(self, key_name, key_usage):
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")
        if key_usage not in self.allowed_key_type:
            raise ValueError("Unknown key usage")
        try:
            validate_key_name(key_name=key_name)
        except TransitError:
            raise ValueError("Invalid key name")
        

    def create_key(self, key_name: str, owner_email: str, key_usage="ENCRYPT_DECRYPT") -> dict:
        """Tạo khóa AES-256 mới và mã hóa nó bằng DEK trước khi lưu xuống DB"""
        
        # This call will auto raise so nothing is needed to be done
        self.check(key_name=key_name, key_usage=key_usage)
        
        # Kiểm tra khóa đã tồn tại chưa
        existing_key = NamedKey.query.filter_by(key_name=key_name, owner_email=owner_email).first()
        if existing_key:
            raise ValueError(f"Lỗi: Key '{key_name}' đã tồn tại!")

        # 1. Sinh ngẫu nhiên khóa AES-256 (32 bytes) cho Client
        raw_aes_key = secrets.token_bytes(32)

        # 2. Mã hóa khóa AES đó bằng DEK hiện hành trong bộ nhớ (AES-256-GCM)
        aesgcm = AESGCM(self.core.dek) #type:ignore
        nonce = os.urandom(12)
        encrypted_key = aesgcm.encrypt(nonce, raw_aes_key, associated_data=bytes(owner_email, 'utf-8'))

        # Trộn nonce (12 bytes) + encrypted_key (chứa sẵn tag) và chuyển sang Base64
        combined_encrypted_key = nonce + encrypted_key
        encrypted_key_material_b64 = base64.b64encode(combined_encrypted_key).decode('utf-8')

        # 3. Lưu xuống Database theo đúng Data Contract
        current_time=datetime.datetime.now()
        new_key = NamedKey(
            key_name=key_name,#type:ignore
            owner_email=owner_email,#type:ignore
            key_usage=key_usage,#type:ignore
            encrypted_key_material_b64=encrypted_key_material_b64,#type:ignore
            created_at=current_time,#type:ignore
            updated_at=current_time#type:ignore
        )
        db.session.add(new_key)
        try:
            db.session.commit()
        except IntegrityError as e:
            db.session.rollback()
            raise ValueError(f"Failed to add key")
        # TUYỆT ĐỐI KHÔNG TRẢ VỀ RAW KEY
        return {
            "key_name": new_key.key_name,
            "owner_email": new_key.owner_email,
            "key_usage": new_key.key_usage,
            "status": "created"
        }

    def list_keys(self, owner_email: str, key_usage:str | None = None) -> list:
        """Liệt kê danh sách tên khóa và key_usage thuộc sở hữu của user"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")
        if key_usage is None:
            keys = NamedKey.query.filter_by(owner_email=owner_email).all()
        else:
            keys = NamedKey.query.filter_by(owner_email=owner_email,key_usage=key_usage).all()
        # Chỉ trả về metadata, không bao giờ trả về key material
        return [
            {
                "key_name": k.key_name,
                "owner_email": k.owner_email,
                "key_usage": k.key_usage
            }
            for k in keys
        ]

    def read_key(self, key_name:str, key_usage:str, owner_email:str):
        self.check(key_name=key_name, key_usage=key_usage)
        
        key = NamedKey.query.filter_by(key_name=key_name, owner_email=owner_email,key_usage=key_usage).first()
        if not key:
            raise ValueError('NOT_FOUND_OR_PERMISSION_DENIED')

        unbase64_encrypted = base64.decodebytes(key.encrypted_key_material_b64.encode('utf-8'))
        nonce, cipher_text = unbase64_encrypted[:12], unbase64_encrypted[12:]
        
        aesgcm = AESGCM(self.core.dek)#type:ignore
        try:
            plain_text_key = aesgcm.decrypt(nonce, cipher_text, bytes(owner_email,'utf-8'))
        except InvalidTag:
            raise ValueError("Failed to decrypt key")
        return plain_text_key
    
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
    
transit_key_obj = TransitKeyManager()