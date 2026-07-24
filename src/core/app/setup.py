import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
# Configs
from .config import DefaultConfig, Config

csrf = CSRFProtect()
db = SQLAlchemy()

login_manager = LoginManager()
bcrypt = Bcrypt()
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
    
    # Blueprints
    from src.auth import auth_bp
    from src.main import main_bf
    from src.core.vault_admin import admin_vault_bf
    # Register other blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bf)
    app.register_blueprint(admin_vault_bf, url_prefix='/admin')
    
    # Connecting other extension to app
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    
    return app

