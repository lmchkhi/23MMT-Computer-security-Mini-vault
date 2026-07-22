from __future__ import annotations

from urllib.parse import urljoin, urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from .decorators import require_browser_auth
from .errors import AuthError
from .forms import LoginForm, LogoutForm, RegistrationForm
from .service import authenticate_token, login_user, register_user, revoke_session

auth_web_bp = Blueprint(
    "auth_web",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/auth-static",
)


def _safe_next_url(target: str | None) -> str | None:
    if not target:
        return None
    host = urlparse(request.host_url)
    candidate = urlparse(urljoin(request.host_url, target))
    if candidate.scheme not in {"http", "https"} or candidate.netloc != host.netloc:
        return None
    return candidate.path + (f"?{candidate.query}" if candidate.query else "")


def _append_field_errors(form: RegistrationForm, error: AuthError) -> None:
    fields = error.details.get("fields", {})
    if not isinstance(fields, dict):
        return
    for field_name, messages in fields.items():
        field = getattr(form, field_name, None)
        if field is None or not isinstance(messages, list):
            continue
        field.errors = list(field.errors) + [str(message) for message in messages]


def _existing_browser_session() -> bool:
    raw_token = request.cookies.get(current_app.config["AUTH_COOKIE_NAME"], "")
    if not raw_token:
        return False
    try:
        authenticate_token(raw_token)
    except AuthError:
        return False
    return True


@auth_web_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET" and _existing_browser_session():
        return redirect(url_for("auth_web.account"))

    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            register_user(
                email=form.email.data,
                passphrase=form.passphrase.data,
                confirm_passphrase=form.confirm_passphrase.data,
            )
        except AuthError as exc:
            if exc.code == "VALIDATION_ERROR":
                _append_field_errors(form, exc)
            else:
                flash(exc.message, "danger")
        else:
            flash("Account created. You can log in now.", "success")
            return redirect(url_for("auth_web.login"))

    return render_template("auth/register.html", form=form)


@auth_web_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" and _existing_browser_session():
        return redirect(url_for("auth_web.account"))

    form = LoginForm()
    lockout_seconds: int | None = None

    if form.validate_on_submit():
        try:
            result = login_user(
                email=form.email.data,
                passphrase=form.passphrase.data,
            )
        except AuthError as exc:
            if exc.code == "ACCOUNT_LOCKED":
                lockout_seconds = int(exc.details.get("retry_after_seconds", 0))
                flash(
                    "Too many failed attempts. This account is temporarily locked.",
                    "danger",
                )
            elif exc.code == "INVALID_CREDENTIALS":
                remaining = int(exc.details.get("remaining_attempts", 0))
                flash(
                    f"Incorrect passphrase. {remaining} attempt(s) remain before lockout.",
                    "danger",
                )
            else:
                flash(exc.message, "danger")
        else:
            destination = _safe_next_url(request.args.get("next")) or url_for(
                "auth_web.account"
            )
            response = redirect(destination)
            response.set_cookie(
                current_app.config["AUTH_COOKIE_NAME"],
                result.token,
                max_age=int(current_app.config["AUTH_TOKEN_TTL_SECONDS"]),
                httponly=True,
                secure=bool(current_app.config["AUTH_COOKIE_SECURE"]),
                samesite="Strict",
                path="/",
            )
            return response

    return render_template(
        "auth/login.html", form=form, lockout_seconds=lockout_seconds
    )


@auth_web_bp.get("/account")
@require_browser_auth
def account():
    return render_template(
        "auth/account.html",
        user=g.current_user,
        expires_at=g.session_expires_at,
        logout_form=LogoutForm(),
    )


@auth_web_bp.post("/logout")
@require_browser_auth
def logout():
    form = LogoutForm()
    if not form.validate_on_submit():
        flash("Invalid logout request.", "danger")
        return redirect(url_for("auth_web.account"))

    revoke_session(g.session_token_hash)
    response = redirect(url_for("auth_web.login"))
    response.delete_cookie(current_app.config["AUTH_COOKIE_NAME"], path="/")
    flash("You have been logged out.", "success")
    return response
