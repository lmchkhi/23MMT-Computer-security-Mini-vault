from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError, IntegerField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from src.storage import User
from src.auth.utils.validation import validate_passphrase

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
    
    def validate_passphrase(self, passphrase):
        if validate_passphrase(passphrase=passphrase.data):
            raise ValidationError("Invalid passphrase")
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("Email has been taken please use another email")
        
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

class TFForm(FlaskForm):
    tf_code = IntegerField("OTP code", validators=[
        DataRequired('Code is required')
        ])
    submit = SubmitField("Submit")