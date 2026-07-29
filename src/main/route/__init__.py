from flask import Blueprint, render_template, g
# from flask_login import login_required
from .errors_handle import error_hander_bf
from src.auth.utils import require_browser_auth
from src.auth.otp.route import check_for_tf
main_bf = Blueprint("main", __name__)

main_bf.register_blueprint(error_hander_bf)

@main_bf.route("/")
@main_bf.route("/index")
@require_browser_auth
def index():
    return render_template("profile.html", current_user=g.auth_user, have_otp=check_for_tf(g.auth_user))

