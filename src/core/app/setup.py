import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_security.decorators import auth_required
from flask_security.utils import hash_password
from flask_security.models import fsqla_v3 as fsqla

# Configs
from .config import DefaultConfig, Config

# Blueprints
from src.auth import auth_bp
from src.main import main_bf

# Extensions
from flask_security.core import Security

from flask_security.datastore import SQLAlchemyUserDatastore



csrf = CSRFProtect()
db = SQLAlchemy()
fsqla.FsModels.set_db_info(db)
login_manager = LoginManager()

security = Security()

# Type is ignore as there is an attribute but pylance said isn't
login_manager.login_view="auth.login" # type: ignore

def create_app(config: Config | None=None) -> Flask:
    app = Flask(__name__)
    
    # Loading default config if config is not selected
    if config is None:
        t_config = DefaultConfig
    else:
        t_config = config
    
    # Appling config to app
    app.config.from_object(t_config)
    app.template_folder = t_config.TEMPLATE_FOLDER_LOCATION
    app.static_folder = t_config.STATIC_FOLDER_LOCATION
    app.instance_path = t_config.INSTANCE_PATH
    
    # Create instance app
    os.makedirs(app.instance_path, exist_ok=True)
    
    # Register other blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bf)
    
    # Connecting other extension to app
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    
    # Import is set here to avoid  circular import
    from src.storage import User, Role
    user_datastore = SQLAlchemyUserDatastore(db,user_model=User,role_model=Role)
    security._datastore = user_datastore
    security.init_app(app)
    
    return app

