from sqlalchemy import ForeignKey, Table
from src.app import db
user_role_table = Table(
    "user_role",
    db.metadata,
    db.Column("user_id", ForeignKey("auth_users.id"), primary_key=True),
    db.Column("role_id", ForeignKey("role.id"), primary_key=True)
)