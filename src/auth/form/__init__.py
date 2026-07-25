from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError, IntegerField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from src.storage import User


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

# class RegistrationForm(FlaskForm):
#     username = StringField('Username', validators=[
#         DataRequired("Username is required"),
#         Length(3, 10, "Username must be %(min)d and %(max)d"),
#         ])
    
#     email = StringField("Email", validators=[
#         DataRequired("Email is required"),
#         Email("Email is invalid")
#         ])
    
#     password = PasswordField("Password", validators=[
#         DataRequired("Password is required"), 
#         Length(8,-1, "Password should be at least %(min)d")
#         ])
    
#     confirm_password = PasswordField("Confirm password", validators=[
#         DataRequired("Confirm password is required"),
#         EqualTo('password', "Confirm password does not match Password")
#     ])
    
#     def validate_email(self, email):
#         user = User.query.filter_by(email=email).first()
#         if user:
#             raise ValidationError("Email have been taken please use another")
    
#     submit = SubmitField("Sign up")

# class LoginForm(FlaskForm):
#     email = StringField("Email", validators=[
#         DataRequired("Email is required"),
#         Email("Email is invalid")
#         ])
    
#     password = PasswordField("Password", validators=[
#         DataRequired("Password is required"), 
#         Length(8,-1, "Password should be at least %(min)d")
#         ])
    
#     remember_me = BooleanField("Remember me")
    
#     submit = SubmitField("Log in")
    
class TFForm(FlaskForm):
    tf_code = IntegerField("OTP code", validators=[
        DataRequired('Code is required')
        ])
    submit = SubmitField("Submit")