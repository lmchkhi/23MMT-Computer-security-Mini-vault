import json
import os
import base64
import datetime
from flask import g
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.storage.kv.models import KVSecret
from src.app import db
from src.storage import AuthSession
from .access_control import authorize_secret_path
from src.core.vault import vault_obj, MiniVaultCore
# from .errors import KvAccessError

class KVEngine:
    def __init__(self, core_vault: MiniVaultCore | None = None):
        """Nhận vào instance của MiniVaultCore để lấy DEK và trạng thái khóa"""
        if core_vault is None:
            core_vault = vault_obj
        self.core = core_vault

    def check_auth(self, token):
        session = AuthSession.query.filter_by(token_hash=token).first()
        if not session:
            return False
        if session.user_id != g.auth_user.id:
            return False
        return True
    
    def write(self, path: str, data: dict, token: str) -> dict:
        """Mã hóa payload JSON và ghi xuống cơ sở dữ liệu"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")
        if not self.check_auth(token):
            raise ValueError("INVALID_TOKEN")
        # If the user does not have the correct email then this will raise an error (KvAccessError)
        authorize_secret_path(path, g.auth_user.email)

            
        # 1. Chuyển JSON thành bytes và tạo Nonce (12 bytes cho GCM)
        payload_bytes = json.dumps(data).encode('utf-8')
        nonce = os.urandom(12)
        
        # 2. Mã hóa bằng DEK
        aesgcm = AESGCM(self.core.dek) # type: ignore
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
        if not self.check_auth(token):
            raise ValueError("INVALID_TOKEN")        
        # If the user does not have the correct email then this will raise an error (KvAccessError)
        authorize_secret_path(path, g.auth_user.email)

        # 1. Truy vấn DB
        secret = KVSecret.query.filter_by(path=path).first()
        if not secret:
            raise ValueError("NOT_FOUND")
            
        try:
            # Treat malformed base64, an altered nonce/ciphertext/tag, and an
            # invalid JSON payload as the same authenticated-storage failure.
            nonce = base64.b64decode(secret.nonce_b64, validate=True)
            ciphertext = base64.b64decode(secret.ciphertext_b64, validate=True)
            tag = base64.b64decode(secret.tag_b64, validate=True)
            encrypted_data = ciphertext + tag
            aesgcm = AESGCM(self.core.dek)  # type: ignore[arg-type]
            decrypted_bytes = aesgcm.decrypt(
                nonce, encrypted_data, associated_data=None
            )
            return json.loads(decrypted_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValueError(
                "Lỗi: Dữ liệu đã bị giả mạo hoặc Tag xác thực không khớp."
            ) from exc

    def delete(self, path: str, token: str) -> dict:
        """Xóa vĩnh viễn bản ghi khỏi cơ sở dữ liệu"""
        if self.core.is_locked:
            raise ValueError("VAULT_LOCKED")
        if not self.check_auth(token):
            raise ValueError("INVALID_TOKEN")        
        # If the user does not have the correct email then this will raise an error (KvAccessError)
        authorize_secret_path(path, g.auth_user.email)
        
        secret = KVSecret.query.filter_by(path=path).first()
        if secret:
            db.session.delete(secret)
            db.session.commit()
        else:
            return {'status': 'No key found'}
        return {"status": "deletion confirmation"}
    
kv_obj = KVEngine()