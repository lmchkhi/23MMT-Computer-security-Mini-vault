from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired("Username is required"),
        Length(3, 10, "Username must be %(min)d and %(max)d"),
        ])
    
    email = StringField("Email", validators=[
        DataRequired("Email is required"),
        Email("Email is invalid")
        ])
    
    password = PasswordField("Password", validators=[
        DataRequired("Password is required"), 
        Length(8,-1, "Password should be at least %(min)d")
        ])
    
    confirm_password = PasswordField("Confirm password", validators=[
        DataRequired("Confirm password is required"),
        EqualTo('password', "Confirm password does not match Password")
    ])
    
    submit = SubmitField("Sign up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[
        DataRequired("Email is required"),
        Email("Email is invalid")
        ])
    
    password = PasswordField("Password", validators=[
        DataRequired("Password is required"), 
        Length(8,-1, "Password should be at least %(min)d")
        ])
    
    remember_me = BooleanField("Remember me")
    
    submit = SubmitField("Log in")