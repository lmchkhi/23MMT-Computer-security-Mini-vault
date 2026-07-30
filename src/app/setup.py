from __future__ import annotations

import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import DeclarativeBase

from .config import DefaultConfig


class Base(DeclarativeBase):
    pass


csrf = CSRFProtect()
db = SQLAlchemy(model_class=Base)


def create_app(config=None) -> Flask:
    config_object = DefaultConfig if config is None else config

    app = Flask(
        __name__,
        template_folder=config_object.TEMPLATE_FOLDER_LOCATION,
        static_folder=config_object.STATIC_FOLDER_LOCATION,
        instance_path=config_object.INSTANCE_PATH,
    )
    app.config.from_object(config_object)
    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize extensions before registering routes that use them.
    db.init_app(app)
    csrf.init_app(app)

    from src.auth import auth_bp
    from src.core.vault_admin import admin_vault_bf
    from src.kv import kv_access_api_bp, kv_access_web_bp
    from src.main import main_bf
    from src.transit import transit_api_bp, transit_web_bp
    from src.workspace import init_workspace_ui

    init_workspace_ui(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bf)
    app.register_blueprint(admin_vault_bf, url_prefix="/admin")
    app.register_blueprint(kv_access_web_bp)
    app.register_blueprint(kv_access_api_bp, url_prefix="/api/kv/access")
    app.register_blueprint(transit_api_bp, url_prefix="/api/transit")
    app.register_blueprint(transit_web_bp, url_prefix="/transit")

    @app.get("/health")
    def health() -> tuple[dict[str, object], int]:
        return {
            "status": "ok",
            "features": ["0.2-user-auth", "1.2-kv-access-control", "2.2-transit"],
        }, 200

    return app
