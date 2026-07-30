from datetime import datetime, timezone
from src.app import db
from sqlalchemy import UniqueConstraint, Index, BigInteger, Text, String
from sqlalchemy.orm import mapped_column, Mapped
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
    
class NamedKey(db.Model):
    __tablename__ = 'named_keys'
    __table_args__ = (
        UniqueConstraint(
            "owner_email", "key_name", name="uq_transit_owner_key_name"
        ),
        Index("idx_named_keys_owner", "owner_email"),
    )
    
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_email: Mapped[str] = mapped_column(String(254), nullable=False)
    key_name: Mapped[str] = mapped_column(String(64), nullable=False)
    key_usage: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_key_material_b64: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_b64: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[int | None] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    
    def to_public_dict(self) -> dict[str, object]:
        return {
            "key_name": self.key_name,
            "owner_email": self.owner_email,
            "key_usage": self.key_usage,
            "revoked": self.revoked_at is not None,
            "created_at": self.created_at,
        }
    # id = db.Column(db.Integer, primary_key=True)
    # key_name = db.Column(db.String(255), unique=True, nullable=False)
    # owner_email = db.Column(db.String(255), nullable=False)
    # key_usage = db.Column(db.String(50), nullable=False, default="ENCRYPT_DECRYPT")
    
    # # Chuỗi Base64 chứa nonce + ciphertext + tag của khóa AES đã được mã hóa bằng DEK
    # encrypted_key_material_b64 = db.Column(db.Text, nullable=False)
    
    # created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))