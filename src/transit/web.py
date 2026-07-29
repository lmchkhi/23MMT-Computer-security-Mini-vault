from __future__ import annotations

import base64
import binascii

from flask import Blueprint, current_app, flash, g, redirect, render_template, url_for

from src.auth.decorators import require_browser_auth
from src.auth.forms import LogoutForm

from .errors import TransitError
from .forms import BootstrapKeyForm, DecryptForm, EncryptForm
from .key_store import bootstrap_demo_key, list_owned_encryption_keys
from .service import decrypt_for_user, encrypt_for_user

transit_web_bp = Blueprint(
    "transit_web",
    __name__,
    template_folder="templates",
)


def _forms() -> tuple[EncryptForm, DecryptForm, BootstrapKeyForm, list[dict[str, object]]]:
    keys = list_owned_encryption_keys(g.current_user.get("email"))
    choices = [(str(key["key_name"]), str(key["key_name"])) for key in keys]
    encrypt_form = EncryptForm(prefix="encrypt")
    encrypt_form.key_name.choices = choices
    decrypt_form = DecryptForm(prefix="decrypt")
    bootstrap_form = BootstrapKeyForm(prefix="bootstrap")
    return encrypt_form, decrypt_form, bootstrap_form, keys


def _render(
    *,
    active_tab: str = "encrypt",
    encrypted_result: dict[str, str] | None = None,
    decrypted_result: dict[str, str] | None = None,
):
    encrypt_form, decrypt_form, bootstrap_form, keys = _forms()
    return render_template(
        "transit/index.html",
        encrypt_form=encrypt_form,
        decrypt_form=decrypt_form,
        bootstrap_form=bootstrap_form,
        keys=keys,
        encrypted_result=encrypted_result,
        decrypted_result=decrypted_result,
        active_tab=active_tab,
        demo_key_enabled=bool(
            current_app.config.get("ENABLE_TRANSIT_DEMO_KEY", False)
        ),
        user=g.current_user,
        logout_form=LogoutForm(),
        active_page="transit",
    )


@transit_web_bp.get("/")
@require_browser_auth
def index():
    return _render()


@transit_web_bp.post("/encrypt")
@require_browser_auth
def encrypt():
    encrypt_form, decrypt_form, bootstrap_form, keys = _forms()
    encrypted_result = None

    if not keys:
        flash("No ENCRYPT_DECRYPT named key is available for this account.", "warning")
    elif encrypt_form.validate_on_submit():
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

    return render_template(
        "transit/index.html",
        encrypt_form=encrypt_form,
        decrypt_form=decrypt_form,
        bootstrap_form=bootstrap_form,
        keys=keys,
        encrypted_result=encrypted_result,
        decrypted_result=None,
        active_tab="encrypt",
        demo_key_enabled=bool(current_app.config.get("ENABLE_TRANSIT_DEMO_KEY", False)),
        user=g.current_user,
        logout_form=LogoutForm(),
        active_page="transit",
    )


@transit_web_bp.post("/decrypt")
@require_browser_auth
def decrypt():
    encrypt_form, decrypt_form, bootstrap_form, keys = _forms()
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

    return render_template(
        "transit/index.html",
        encrypt_form=encrypt_form,
        decrypt_form=decrypt_form,
        bootstrap_form=bootstrap_form,
        keys=keys,
        encrypted_result=None,
        decrypted_result=decrypted_result,
        active_tab="decrypt",
        demo_key_enabled=bool(current_app.config.get("ENABLE_TRANSIT_DEMO_KEY", False)),
        user=g.current_user,
        logout_form=LogoutForm(),
        active_page="transit",
    )


@transit_web_bp.post("/dev/bootstrap-key")
@require_browser_auth
def dev_bootstrap_key():
    _, _, form, _ = _forms()
    if not bool(current_app.config.get("ENABLE_TRANSIT_DEMO_KEY", False)):
        return {"error": {"code": "NOT_FOUND", "message": "Endpoint not found"}}, 404
    if not form.validate_on_submit():
        flash("Demo key name is invalid.", "danger")
        return redirect(url_for("transit_web.index"))

    try:
        key = bootstrap_demo_key(
            owner_email=g.current_user.get("email"),
            key_name=form.key_name.data,
        )
    except TransitError as exc:
        flash(exc.message, "danger")
    else:
        flash(f"Demo key {key['key_name']} is ready.", "success")
    return redirect(url_for("transit_web.index"))
