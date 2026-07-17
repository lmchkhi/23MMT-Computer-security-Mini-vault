from flask import Flask, render_template, flash, redirect, url_for
from dotenv import load_dotenv
from forms import RegistrationForm, LoginForm
from flask_wtf.csrf import CSRFProtect
import os
app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)


load_dotenv(".env")
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["WTF_CSRF_SECRET_KEY"] = os.environ["WTF_CSRF_SECRET_KEY"]
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["SQLALCHEMY_DATABASE_URI"]

@app.route("/")
def hello_world():
    return render_template("profile.html")

@app.route("/register", methods=["GET", "POST"])
def reigister():
    form = RegistrationForm()
    if form.validate_on_submit():
        redirect(url_for("/login"))
    
    return render_template("register.html", form=form)

@app.route("/login")
def login():
    
    return render_template("login.html")

@app.errorhandler(404)
def error_handle(error):
    return render_template("404.html")

if __name__ == "__main__":
    app.run(debug=True)
