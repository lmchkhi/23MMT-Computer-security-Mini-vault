from flask import Blueprint, render_template, request, url_for, redirect
from flask_login import login_user
from src.auth.form import RegistrationForm, LoginForm

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        return redirect(url_for("auth.login"))
    
    return render_template("register.html", form=form)

@auth_bp.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        pass
        
    return render_template("login.html", form=form)
