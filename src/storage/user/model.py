from src.core.app import db
from sqlalchemy import String, LargeBinary, ForeignKey, UUID
import uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from flask_security.models import fsqla_v3 as fsqla
from src.storage.roles import Role

class User(db.Model, fsqla.FsUserMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password: Mapped[bytes] = mapped_column(LargeBinary(72))
    role: Mapped[Role] = mapped_column(ForeignKey("role.id"))


