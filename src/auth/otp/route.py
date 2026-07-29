import io
import pyqrcode
import datetime
import jwt
import base64
from cryptography.fernet import Fernet, InvalidToken
from pyotp import TOTP, parse_uri, random_base32
from flask import Blueprint, g, redirect, url_for, request, make_response, current_app, render_template, flash

from src.auth.form import TFForm
from src.app import db
from src.storage import User
from src.core import vault_obj
from src.auth.utils import require_browser_auth
from src.auth.utils.misc import get_valid_next_url, _user_login

otp_auth_bp = Blueprint("otp", __name__)

def check_for_tf(user: User):
    methods = user.required_login_step.split(',')
    if 'tf-otp' in methods:
        return True
    return False

@otp_auth_bp.route('/tf-unregister')
@require_browser_auth
def unregister_tf():
    current_user = g.auth_user
    user = User.query.filter_by(email=current_user.email).first()
    if not user or not check_for_tf(user):
        return redirect(url_for("main.index"))
    methods = current_user.required_login_step
    new_methods = ''.join(i + ',' for i in methods if i != 'tf-otp')[:-1]
    # we get only from start to end - 2
    # because the last character is always a comma
    current_user.required_login_step = new_methods
    current_user.otp_uri = ''
    # db.session.add(current_user)
    db.session.commit()
    return redirect(url_for("main.index"))
    

@otp_auth_bp.route('/tf-register', methods=["GET","POST"])
@require_browser_auth
def register_tf():
    current_user = g.auth_user
    # Init otp code if not register
    if not request.cookies.get('code'):
        secret = random_base32()
        time_OTP = TOTP(secret)
        time_link = time_OTP.provisioning_uri(name=current_user.email, issuer_name='minivault-otp')
    else:
        # Take the previously generated value from cookie
        jwt_obj = request.cookies.get('code','')
        
        try:
            claims = jwt.decode(jwt_obj,
                       current_app.config.get('SECRET_KEY') or 'secret123!',
                           algorithms=["HS256"],
                           audience=current_user.email,
                           issuer="mini-vault-project")
        except jwt.DecodeError:
            claims = None
            
        if claims:
            time_OTP = parse_uri(str(claims.get('link')))
            time_link = time_OTP.provisioning_uri(name=current_user.email, issuer_name='minivault-otp') #type: ignore
        else:
            response = redirect(url_for("auth.register_tf"))
            response.delete_cookie('code')
            return response
    
    # Validating form input
    form = TFForm()
    if form.validate_on_submit() and not vault_obj.is_locked:
        code = form.tf_code.data
        if time_OTP.verify(str(code)): #type: ignore
            fernet_enc = Fernet(base64.urlsafe_b64encode(vault_obj.dek)) #type: ignore
            encrypted_link = fernet_enc.encrypt(time_link.encode('utf-8'))
            current_user.otp_uri = encrypted_link.decode('utf-8')
            current_user.required_login_step += ',tf-otp'
            
            db.session.add(current_user)
            db.session.commit()
            response = redirect(url_for("main.index"))
            response.delete_cookie('code')
            return response
        else:
            error_list = list(form.tf_code.errors)
            error_list.append("Invalid code")
            form.tf_code.errors = tuple(error_list)
    
    # Generating QR
    qr_obj = pyqrcode.create(time_link)
    
    io_obj = io.BytesIO()
    qr_obj.svg(io_obj, 
               scale=100,
               omithw=True,
               lineclass='qr-max-size',
               svgclass='qr-max-size', xmldecl=False)
    qr_str = ''.join(chr(i) for i in io_obj.getvalue())
    
    # Making response 
    response = make_response(render_template('tf-register.html', qr_code=qr_str, form=form))
    if not request.cookies.get('code'):
        jwt_obj = jwt.encode(
            {
                "iss": "mini-vault-project",
                "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=5),
                "nbf": datetime.datetime.now(tz=datetime.timezone.utc),
                'aud': current_user.email,
                "iat": datetime.datetime.now(tz=datetime.timezone.utc),
                "sub": "tf-otp-setup",
                "link": time_link
            },
            current_app.config.get("SECRET_KEY") or 'secret123!',
            algorithm="HS256"
        )
        response.set_cookie('code', jwt_obj, 
                            max_age=datetime.timedelta(minutes=5), 
                            expires=datetime.datetime.now() + datetime.timedelta(5)
                            )
    return response


@otp_auth_bp.route("/tf-login",methods=["GET","POST"])
def tf_login():
    
    token = request.cookies.get("otp-login-token")
    
    # There is no user email 
    if token is None:
        return redirect(url_for('auth.login'))
    try:
        jwt_obj = jwt.decode(
            token, 
            current_app.config.get("SECRET_KEY", "secret123!"),
            issuer='mini-vault-project',
            subject='tf-user',
            algorithms=['HS256']
            )
    except jwt.DecodeError as e:
        response = redirect(url_for('auth.login'))
        response.delete_cookie('otp-login-token')
        flash('OTP session has expired. Please enter your passwrod again', 'danger')
        return response
    
    user_email = jwt_obj.get('email')

    form = TFForm()
    if form.validate_on_submit() and not vault_obj.is_locked:
        user = User.query.filter_by(email=user_email).first()
        
        otp_uri = None
        if user and check_for_tf(user):
            fernet_dec = Fernet(base64.urlsafe_b64encode(vault_obj.dek)) #type: ignore
            try:
                otp_uri = fernet_dec.decrypt(user.otp_uri).decode()
            except InvalidToken:
                pass
        
        if otp_uri and user:
            totp = parse_uri(otp_uri)
            if totp and totp.verify(str(form.tf_code.data)): # type: ignore
                # Validate next parameter
                next_url = request.args.get('next')
                response = redirect(get_valid_next_url(next_url) or url_for("main.index"))
                response = _user_login(user, response)
                response.delete_cookie('email')
                
                return response
        flash("Invalid TOTP", category='danger')
    if vault_obj.is_locked:
        flash("Vault is lock. Please contact admin to unlock vault", "warning")   
    return render_template("tf-login.html",form=form)