"""Shared Flask extensions.

The final team branch should create each extension exactly once and import these
objects from every feature module. This prevents separate SQLAlchemy metadata
registries when branches are merged.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
csrf = CSRFProtect()
