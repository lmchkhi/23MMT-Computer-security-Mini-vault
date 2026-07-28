
from src.app import db

from sqlalchemy import String, ForeignKey, BigInteger, Index, Text
import uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional
from flask_login import UserMixin
from src.storage.roles import Role

from src.storage.bridge import user_role_table

class User(db.Model):
    __tablename__ = "auth_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    # username: Mapped[str] = mapped_column(String(50), unique=False)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    roles: Mapped[list[Role]] = relationship(secondary=user_role_table, back_populates="users")
    alternitive_id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4)

    otp_uri:Mapped[Optional[str]] = mapped_column(unique=False)
    required_login_step:Mapped[str] = mapped_column(unique=False, default="None")
    
    failed_attempts: Mapped[int] = mapped_column(
        nullable=False, default=0
    )
    lock_until: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)

    sessions: Mapped[list["AuthSession"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def to_public_dict(self) -> dict[str, object]:
        return {"id": self.id, "email": self.email}
    

class AuthSession(db.Model):
    """Opaque session token metadata.

    Only a SHA-256 digest is persisted. The raw token is returned once to the
    client or placed in an HttpOnly browser cookie.
    """

    __tablename__ = "auth_sessions"
    __table_args__ = (
        Index("idx_auth_sessions_user_id", "user_id"),
        Index("idx_auth_sessions_expires_at", "expires_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")
