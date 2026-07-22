from flask import Blueprint, render_template
from flask_login import login_required
from .errors_handle import error_hander_bf

main_bf = Blueprint("main", __name__)

main_bf.register_blueprint(error_hander_bf)

@main_bf.route("/")
@main_bf.route("/index")
@login_required
def index():
    return render_template("profile.html")
