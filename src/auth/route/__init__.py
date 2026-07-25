import datetime
import jwt
from flask import Blueprint, render_template, request, url_for, redirect, flash, current_app, g

from src.auth.form import RegistrationForm, LoginForm, TFForm
from src.storage import User
from src.core import vault_obj
from src.app import csrf

from src.auth.utils.errors import AuthError
from src.auth.otp import check_for_tf, otp_auth_bp
from src.auth.utils import require_browser_auth, revoke_session, register_user, check_password
from src.auth.utils.misc import _append_field_errors, get_valid_next_url, _user_login

from .api import auth_api_bp

auth_bp = Blueprint('auth', __name__)
auth_bp.register_blueprint(otp_auth_bp)
auth_bp.register_blueprint(auth_api_bp, url_prefix='/api/auth')

# The JSON API does not use browser cookies. Bearer tokens protect private
# endpoints, so Flask-WTF CSRF remains enabled only for server-rendered forms.
csrf.exempt(auth_api_bp)

# def is_safe_url(url, alternitive_url=None):
#     # if alternitive_url is None:
#     #     alternitive_url = current_app.config.get('SERVER_NAME')
#     try:
#         ref_url = urlparse(alternitive_url or request.host_url)

#         test_url = urlparse(urljoin(request.host_url, url))
#         return (
#             test_url.scheme in ('http', 'https') and 
#             ref_url.netloc == test_url.netloc
#         )
#     except Exception:
#         return False

# # def is_safe_api_url(url):
# #     return is_safe_url(url, current_app.config.get('API_SERVER_NAME'))

# def get_valid_next_url(next_url:str|None):
#     if next_url and is_safe_url(next_url):
#         next = next_url
#     else:
#         next = None
#     return next

# def _user_login(user: User, response):
#     result = login_user(user=user)
#     response.set_cookie(
#         current_app.config["AUTH_COOKIE_NAME"],
#         result.token,
#         max_age=int(current_app.config["AUTH_TOKEN_TTL_SECONDS"]),
#         httponly=True,
#         secure=bool(current_app.config["AUTH_COOKIE_SECURE"]),
#         samesite="Strict",
#         path="/",
#     )
#     return response

# def _append_field_errors(form: RegistrationForm, error: AuthError) -> None:
#     fields = error.details.get("fields", {})
#     if not isinstance(fields, dict):
#         return
#     for field_name, messages in fields.items():
#         field = getattr(form, field_name, None)
#         if field is None or not isinstance(messages, list):
#             continue
#         field.errors = list(field.errors) + [str(message) for message in messages]

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            register_user(
                email=form.email.data,
                passphrase=form.passphrase.data,
                confirm_passphrase=form.confirm_passphrase.data
            )
            flash("Account created. You can log in now.", "success")
            return redirect(url_for("auth.login"))
        except AuthError as e:
            if e.code == "VALIDATION_ERROR":
                _append_field_errors(form, e)

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET","POST"])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        # Getting data from form
        email,password = form.email.data, form.passphrase.data
        
        # Checking if user acutally exists
        corresponding_user = User.query.filter_by(email=email).first()
        error_mes = ''
        try:
            corresponding_user = check_password(email=email, passphrase=password)
        except AuthError as e:
            error_mes = e
            corresponding_user = None
            
        if corresponding_user:
            
            next_url = request.args.get('next')
            
            if check_for_tf(corresponding_user): # redirect user to two factor page
                response = redirect(url_for("auth.otp.tf_login", next=next_url or ''))
                # Setting cookie value to allow the next phase to identify user
                timeout = 3
                jwt_obj = jwt.encode(
                    {
                        "iss": "mini-vault-project",
                        "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=timeout),
                        "nbf": datetime.datetime.now(tz=datetime.timezone.utc),
                        'email': email,
                        "iat": datetime.datetime.now(tz=datetime.timezone.utc),
                        "sub": "tf-user",
                    },
                    current_app.config['SECRET_KEY'] or 'sercret123!',
                    algorithm='HS256'
                    )
                
                response.set_cookie('otp-login-token',
                                    jwt_obj, # TODO: need to change to jwt token with timeout to make sure user is we sent
                                    datetime.timedelta(minutes=timeout), # max age
                                    datetime.datetime.now() + datetime.timedelta(minutes=timeout) # expire time
                                    )
                return response
            
            
            response = redirect(get_valid_next_url(next_url) or url_for("main.index"))
            response = _user_login(corresponding_user, response)
            return response
        
        if error_mes and error_mes.code == "ACCOUNT_LOCKED":
            flash(f"You have enter the passpharse wrong 5 time, please wait for ({error_mes.details.get("retry_after_seconds", '-1')} seconds to login again)",
                    category="danger")
        else:
            flash("Username or password is wrong", category="text-danger")
            
    if vault_obj.is_locked:
        flash("Vault is lock. Please contact admin to unlock vault", "warning")
        
    return render_template("login.html", form=form)



@auth_bp.route("/logout")
@require_browser_auth
def logout():
    token = g.session_token_hash
    if token:
        revoke_session(token_hash=token)
    response = redirect(url_for("auth.login"))
    response.delete_cookie(current_app.config["AUTH_COOKIE_NAME"], path="/")
    flash("You have been logged out.", "success")
    return response