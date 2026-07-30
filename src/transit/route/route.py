from flask import Blueprint, current_app, flash, g, redirect, render_template, url_for
import base64
import binascii
from src.auth.utils.decorators import require_browser_auth
from src.transit.form import EncryptForm, CreateKeyForm, DecryptForm
from src.transit.utils.errors import TransitError
from src.transit.utils import encrypt_for_user, decrypt_for_user
from src.transit.utils import transit_key_obj
transit_web_bp = Blueprint(
    "transit_web",
    __name__,
    template_folder="templates",
)

@transit_web_bp.route('/list-key')
@require_browser_auth
def list_key():
    key_list = transit_key_obj.list_keys(g.auth_user.email)
    return render_template('transit/list-key.html', key_list=key_list)

@transit_web_bp.route('/revoke/<string:key_name>', methods=["POST"])
@require_browser_auth
def revoke_key(key_name):
    try:
        transit_key_obj.revoke_key(key_name, g.auth_user.email)
    except ValueError as e:
        if str(e) == 'NOT_FOUND_OR_PERMISSION_DENIED':
            flash("No key found", "danger")
        else:
            flash('Vault is locked. Please contact admin', 'danger')
    return redirect(url_for('transit_web.list_key'))

@transit_web_bp.route('/create-key', methods=["GET","POST"])
@require_browser_auth
def create_key():
    form = CreateKeyForm()
    
    if form.validate_on_submit():
        try:
            transit_key_obj.create_key(form.key_name.data, g.auth_user.email)
            flash('Key created successfully', 'success')
            return redirect(url_for('transit_web.list_key')) 
        except ValueError as e:
            flash(str(e),'danger')
    return render_template('transit/create_key.html',form=form)

@transit_web_bp.route('/encrypt',methods=["GET","POST"])
@require_browser_auth
def encrypt():
    encrypt_form = EncryptForm()
    keys = transit_key_obj.list_keys(g.auth_user.email, "ENCRYPT_DECRYPT")
    choices = [(str(key["key_name"]), str(key["key_name"])) for key in keys]
    encrypt_form.key_name.choices = choices
    encrypted_result = None
    
    if encrypt_form.validate_on_submit():
        
        try:
            if encrypt_form.input_format.data == "base64":
                # Validate now so UI errors are clear; service validates again.
                base64.b64decode(encrypt_form.plaintext.data, validate=True)
                plaintext_b64 = encrypt_form.plaintext.data
            else:
                plaintext_b64 = base64.b64encode(
                    encrypt_form.plaintext.data.encode("utf-8")
                ).decode("ascii")

            result = encrypt_for_user(
                owner_email=g.current_user.get("email"),
                key_name=encrypt_form.key_name.data,
                plaintext_b64=plaintext_b64,
            )
        except (binascii.Error, ValueError):
            flash("Plaintext must be valid base64 for Base64 input mode.", "danger")
        except TransitError as exc:
            flash(exc.message, "danger")
        else:
            encrypted_result = {
                "key_name": result.key_name,
                "ciphertext": result.ciphertext,
            }
            flash("Plaintext encrypted and authenticated.", "success")
    return render_template('transit/encrypt.html',encrypt_form=encrypt_form, encrypted_result=encrypted_result)

@transit_web_bp.route('/decrypt',methods=["GET","POST"])
@require_browser_auth
def decrypt():
    decrypt_form = DecryptForm()
    decrypted_result = None

    if decrypt_form.validate_on_submit():
        try:
            result = decrypt_for_user(
                owner_email=g.current_user.get("email"),
                ciphertext=decrypt_form.ciphertext.data,
            )
        except TransitError as exc:
            flash(exc.message, "danger")
        else:
            try:
                text = result.plaintext.decode("utf-8")
                is_utf8 = True
            except UnicodeDecodeError:
                text = ""
                is_utf8 = False
            decrypted_result = {
                "key_name": result.key_name,
                "plaintext_b64": result.plaintext_b64,
                "plaintext_text": text,
                "is_utf8": is_utf8,
            }
            flash("Ciphertext integrity verified and plaintext recovered.", "success")
    
    return render_template('transit/decrypt.html',decrypt_form=decrypt_form, decrypted_result=decrypted_result)

