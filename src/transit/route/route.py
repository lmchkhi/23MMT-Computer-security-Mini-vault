from __future__ import annotations

import base64
import binascii

from flask import Blueprint, current_app, flash, g, redirect, render_template, url_for

from src.auth.utils.decorators import require_browser_auth
from src.transit.form import BootstrapKeyForm, CreateKeyForm, DecryptForm, EncryptForm
from src.transit.utils import decrypt_for_user, encrypt_for_user, transit_key_obj
from src.transit.utils.errors import TransitError

transit_web_bp = Blueprint("transit_web", __name__, template_folder="templates")


def _forms() -> tuple[EncryptForm, DecryptForm, BootstrapKeyForm, list[dict[str, object]]]:
    encrypt_form = EncryptForm(prefix="encrypt")
    decrypt_form = DecryptForm(prefix="decrypt")
    bootstrap_form = BootstrapKeyForm(prefix="bootstrap")
    keys = transit_key_obj.list_keys(g.auth_user.email, "ENCRYPT_DECRYPT")
    encrypt_form.key_name.choices = [
        (str(key["key_name"]), str(key["key_name"])) for key in keys
    ]
    return encrypt_form, decrypt_form, bootstrap_form, keys


def _render_index(
    *,
    active_tab: str,
    encrypt_form: EncryptForm | None = None,
    decrypt_form: DecryptForm | None = None,
    bootstrap_form: BootstrapKeyForm | None = None,
    keys: list[dict[str, object]] | None = None,
    encrypted_result: dict[str, object] | None = None,
    decrypted_result: dict[str, object] | None = None,
):
    if any(value is None for value in (encrypt_form, decrypt_form, bootstrap_form, keys)):
        encrypt_form, decrypt_form, bootstrap_form, keys = _forms()
    return render_template(
        "transit/index.html",
        active_tab=active_tab,
        active_page="transit",
        user=g.auth_user,
        encrypt_form=encrypt_form,
        decrypt_form=decrypt_form,
        bootstrap_form=bootstrap_form,
        keys=keys,
        encrypted_result=encrypted_result,
        decrypted_result=decrypted_result,
        demo_key_enabled=bool(current_app.config.get("ENABLE_TRANSIT_DEMO_KEY", False)),
    )


@transit_web_bp.get("/")
@require_browser_auth
def index():
    try:
        return _render_index(active_tab="encrypt")
    except ValueError as exc:
        flash("Vault is locked." if str(exc) == "VAULT_LOCKED" else "Transit is unavailable.", "danger")
        return render_template(
            "transit/index.html",
            active_tab="encrypt",
            active_page="transit",
            user=g.auth_user,
            encrypt_form=EncryptForm(prefix="encrypt"),
            decrypt_form=DecryptForm(prefix="decrypt"),
            bootstrap_form=BootstrapKeyForm(prefix="bootstrap"),
            keys=[],
            encrypted_result=None,
            decrypted_result=None,
            demo_key_enabled=False,
        )


@transit_web_bp.route("/encrypt", methods=["GET", "POST"])
@require_browser_auth
def encrypt():
    try:
        encrypt_form, decrypt_form, bootstrap_form, keys = _forms()
    except ValueError as exc:
        flash("Vault is locked." if str(exc) == "VAULT_LOCKED" else "Transit is unavailable.", "danger")
        return redirect(url_for("transit_web.index"))

    encrypted_result = None
    if encrypt_form.validate_on_submit():
        try:
            if encrypt_form.input_format.data == "base64":
                base64.b64decode(encrypt_form.plaintext.data, validate=True)
                plaintext_b64 = encrypt_form.plaintext.data
            else:
                plaintext_b64 = base64.b64encode(
                    encrypt_form.plaintext.data.encode("utf-8")
                ).decode("ascii")

            result = encrypt_for_user(
                owner_email=g.auth_user.email,
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

    return _render_index(
        active_tab="encrypt",
        encrypt_form=encrypt_form,
        decrypt_form=decrypt_form,
        bootstrap_form=bootstrap_form,
        keys=keys,
        encrypted_result=encrypted_result,
    )


@transit_web_bp.route("/decrypt", methods=["GET", "POST"])
@require_browser_auth
def decrypt():
    try:
        encrypt_form, decrypt_form, bootstrap_form, keys = _forms()
    except ValueError as exc:
        flash("Vault is locked." if str(exc) == "VAULT_LOCKED" else "Transit is unavailable.", "danger")
        return redirect(url_for("transit_web.index"))

    decrypted_result = None
    if decrypt_form.validate_on_submit():
        try:
            result = decrypt_for_user(
                owner_email=g.auth_user.email,
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

    return _render_index(
        active_tab="decrypt",
        encrypt_form=encrypt_form,
        decrypt_form=decrypt_form,
        bootstrap_form=bootstrap_form,
        keys=keys,
        decrypted_result=decrypted_result,
    )


@transit_web_bp.post("/dev/bootstrap-key")
@require_browser_auth
def dev_bootstrap_key():
    if not current_app.config.get("ENABLE_TRANSIT_DEMO_KEY", False):
        flash("Demo key creation is disabled.", "danger")
        return redirect(url_for("transit_web.index"))
    form = BootstrapKeyForm(prefix="bootstrap")
    if form.validate_on_submit():
        try:
            transit_key_obj.create_key(form.key_name.data, g.auth_user.email)
            flash("Demo key created.", "success")
        except ValueError as exc:
            flash(str(exc), "danger")
    return redirect(url_for("transit_web.index"))


# Legacy key-management pages kept for branch compatibility.
@transit_web_bp.get("/list-key")
@require_browser_auth
def list_key():
    key_list = transit_key_obj.list_keys(g.auth_user.email)
    return render_template("transit/list-key.html", key_list=key_list)


@transit_web_bp.post("/revoke/<string:key_name>")
@require_browser_auth
def revoke_key(key_name):
    try:
        transit_key_obj.revoke_key(key_name, g.auth_user.email)
    except ValueError as exc:
        flash("No key found" if str(exc) == "KEY_NOT_FOUND_OR_DENIED" else str(exc), "danger")
    return redirect(url_for("transit_web.list_key"))


@transit_web_bp.route("/create-key", methods=["GET", "POST"])
@require_browser_auth
def create_key():
    form = CreateKeyForm()
    if form.validate_on_submit():
        try:
            transit_key_obj.create_key(form.key_name.data, g.auth_user.email)
            flash("Key created successfully", "success")
            return redirect(url_for("transit_web.list_key"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("transit/create_key.html", form=form)
