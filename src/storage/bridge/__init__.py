from sqlalchemy import ForeignKey, Table
from src.core.app import db
user_role_table = Table(
    "user_role",
    db.metadata,
    db.Column("user_id", ForeignKey("user.id"), primary_key=True),
    db.Column("role_id", ForeignKey("role.id"), primary_key=True)
)