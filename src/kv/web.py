from __future__ import annotations

from flask import Blueprint, flash, g, render_template

from src.auth.decorators import require_browser_auth
from src.auth.forms import LogoutForm

from .access_control import authorize_secret_path
from .errors import KvAccessError
from .forms import OwnershipCheckForm

kv_access_web_bp = Blueprint(
    "kv_access_web",
    __name__,
    template_folder="templates",
)


@kv_access_web_bp.route("/", methods=["GET", "POST"])
@require_browser_auth
def index():
    form = OwnershipCheckForm()
    result: dict[str, object] | None = None

    if form.validate_on_submit():
        try:
            authorized = authorize_secret_path(
                form.path.data, g.current_user.get("email")
            )
        except KvAccessError as exc:
            result = {
                "allowed": False,
                "code": exc.code,
                "message": exc.message,
            }
            flash(
                "Access denied before any secret lookup or decryption was attempted.",
                "danger",
            )
        else:
            result = {
                "allowed": True,
                "path": authorized.path,
                "owner_email": authorized.owner_email,
                "relative_path": authorized.relative_path,
            }
            flash("Path belongs to your namespace.", "success")

    if not form.path.data:
        form.path.data = f"secret/{g.current_user['email']}/db"

    return render_template(
        "kv/access_control.html",
        form=form,
        result=result,
        user=g.current_user,
        logout_form=LogoutForm(),
        active_page="kv",
    )
