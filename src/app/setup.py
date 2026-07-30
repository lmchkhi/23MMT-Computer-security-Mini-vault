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
    from src.kv import kv_access_api_bp, kv_access_web_bp
    from src.transit import transit_api_bp, transit_web_bp
    # Register other blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bf)
    app.register_blueprint(admin_vault_bf, url_prefix='/admin')
    app.register_blueprint(kv_access_web_bp)
    app.register_blueprint(kv_access_api_bp)
    app.register_blueprint(transit_api_bp, url_prefix="/api/transit")
    app.register_blueprint(transit_web_bp, url_prefix="/transit")

    
    @app.get("/health")
    def health() -> tuple[dict[str, object], int]:
        return {
            "status": "ok",
            "features": ["0.2-user-auth", "1.2-kv-access-control", "2.2-transit"],
        }, 200
    # Connecting other extension to app
    db.init_app(app)
    csrf.init_app(app)

    return app

