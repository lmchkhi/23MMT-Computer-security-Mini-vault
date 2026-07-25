import os
from flask import Flask
from sqlalchemy.orm import DeclarativeBase
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# Configs
from .config import DefaultConfig

class Base(DeclarativeBase):
    pass

csrf = CSRFProtect()
db = SQLAlchemy(model_class=Base)

def create_app(config=None) -> Flask:
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
    
    @app.get("/health")
    def health() -> tuple[dict[str, str], int]:
        return {"status": "ok", "feature": "0.2-user-auth"}, 200
    # Connecting other extension to app
    db.init_app(app)
    csrf.init_app(app)
    
    # The JSON API does not use browser cookies. Bearer tokens protect private
    # endpoints, so Flask-WTF CSRF remains enabled only for server-rendered forms.
    from src.auth.route import auth_api_bp 
    csrf.exempt(auth_api_bp)

    return app

