from src.core.app import db
from sqlalchemy import String
from flask_security.models import fsqla_v3 as fsqla
from sqlalchemy.orm import Mapped, mapped_column

class Role(db.Model, fsqla.FsRoleMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(10), unique=True)
