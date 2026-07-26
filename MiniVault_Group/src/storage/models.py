from datetime import datetime, timezone
from src.storage.db import db

class KVSecret(db.Model):
    __tablename__ = 'kv_secrets'
    
    id = db.Column(db.Integer, primary_key=True)
    # Đường dẫn duy nhất đóng vai trò là khóa (ví dụ: secret/alice@example.com/db)
    path = db.Column(db.String(255), unique=True, nullable=False)
    
    # Lưu trữ các thành phần mã hóa dưới dạng Base64
    nonce_b64 = db.Column(db.String(50), nullable=False)
    ciphertext_b64 = db.Column(db.Text, nullable=False)
    tag_b64 = db.Column(db.String(50), nullable=False)
    
    # Lưu thời gian tạo và cập nhật
    # created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
