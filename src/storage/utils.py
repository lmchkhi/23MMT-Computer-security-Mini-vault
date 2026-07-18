from flask_security.utils import hash_password
from src.core.app import create_app, db
from src.core.app import security

# This should only be run when database is deleted or is first init
def init_database():
    app = create_app()
    with app.app_context():
        db.create_all()
        if not security.datastore.find_user(email="test@me.com"):
            security.datastore.create_user(email="test@me.com", password=hash_password("password"))