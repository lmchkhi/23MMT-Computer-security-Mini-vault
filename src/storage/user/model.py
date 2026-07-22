
from src.core.app import db

from sqlalchemy import String, LargeBinary, ForeignKey, UUID
import uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from typing import Optional
from flask_login import UserMixin
from src.storage.roles import Role

from src.storage.bridge import user_role_table

class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=False)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password: Mapped[str] = mapped_column(String(72))
    # role: Mapped[Role] = mapped_column(ForeignKey("role.id"))
    roles: Mapped[list[Role]] = relationship(secondary=user_role_table, back_populates="users")
    alternitive_id: Mapped[uuid.UUID] = mapped_column(default=uuid.uuid4)

    otp_uri:Mapped[Optional[str]] = mapped_column(unique=False)
    required_login_step:Mapped[str] = mapped_column(unique=False, default="None")
    
    def get_id(self):
        return str(self.alternitive_id)
        #3 return super().get_id()
    