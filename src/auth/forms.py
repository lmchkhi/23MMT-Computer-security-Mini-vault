from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegistrationForm(FlaskForm):
    email = EmailField(
        "Email address",
        validators=[
            DataRequired(message="Email is required"),
            Email(message="Email format is invalid"),
            Length(max=254),
        ],
    )
    passphrase = PasswordField(
        "Passphrase",
        validators=[DataRequired(message="Passphrase is required"), Length(max=256)],
    )
    confirm_passphrase = PasswordField(
        "Confirm passphrase",
        validators=[
            DataRequired(message="Passphrase confirmation is required"),
            EqualTo(
                "passphrase", message="Passphrase confirmation does not match"
            ),
        ],
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    email = EmailField(
        "Email address",
        validators=[
            DataRequired(message="Email is required"),
            Email(message="Email format is invalid"),
            Length(max=254),
        ],
    )
    passphrase = PasswordField(
        "Passphrase",
        validators=[DataRequired(message="Passphrase is required"), Length(max=256)],
    )
    submit = SubmitField("Log in")


class LogoutForm(FlaskForm):
    submit = SubmitField("Log out")
