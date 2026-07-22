from flask_security.utils import hash_password
from src.core.app import create_app, db
from flask_bcrypt import generate_password_hash
from . import User, Role


def init_database():
    # This should only be run when database is deleted or is first init
    app = create_app()
    with app.app_context():
        db.create_all()
        
        if not Role.query.filter_by(name="admin").first():
            # type is ignore because pylance does not recongize the attribute
            role1 = Role(name="admin") #type: ignore
            db.session.add(role1)
            db.session.commit()
            
        if not Role.query.filter_by(name="user").first():
            role2 = Role(name="user") #type: ignore
            db.session.add(role2)
            db.session.commit()
            
        if not User.query.filter_by(email='admin@admin.vn').first():
            # type is ignore because pylance does not recongize the attribute
            user1 = User(username="admin", email="admin@admin.vn", password=generate_password_hash('12345678').decode()) #type: ignore
            user1.roles = [Role.query.filter_by(name="admin").first()] #type: ignore
            db.session.add(user1)
            db.session.commit()
        
        if not User.query.filter_by(email='user1@user.vn').first():
            # type is ignore because pylance does not recongize the attribute
            user1 = User(username="user1", email="user1@user.vn", password=generate_password_hash('12345678').decode()) #type: ignore
            user1.roles = [Role.query.filter_by(name="user").first()] #type: ignore
            db.session.add(user1)
            db.session.commit()
            
def drop_database():
    # This should only be run after database created and need reset
    app = create_app()
    with app.app_context():
        db.drop_all()