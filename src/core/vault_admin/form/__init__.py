from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Length, Email

class VaultKeyForm(FlaskForm):
    master_passkey = PasswordField("Master passkey", validators=[DataRequired()])
    submit = SubmitField("Submit")