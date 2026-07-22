from src.core.app import db
from sqlalchemy import String

from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.storage.bridge import user_role_table

class Role(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(10), unique=True)
    users: Mapped[list["User"]] = relationship(secondary=user_role_table,back_populates="roles") #type: ignore