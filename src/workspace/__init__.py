from __future__ import annotations

from flask import Blueprint, Flask

workspace_ui_bp = Blueprint(
    "workspace_ui",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/workspace-static",
)


def init_workspace_ui(app: Flask) -> None:
    app.register_blueprint(workspace_ui_bp)
