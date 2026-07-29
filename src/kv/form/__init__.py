from flask_wtf import FlaskForm
from wtforms.validators import DataRequired
from wtforms import StringField, PasswordField, ValidationError, SubmitField
from src.kv.utils.access_control import parse_secret_path, KvAccessError

class SecretForm(FlaskForm):
    """
    Defines the structure for adding/editing secrets.
    """
    path = StringField(
        label="Secret Path",
        validators=[
            DataRequired(),
        ],
        
    )
    secret_value = PasswordField(
        label="Secret Value",
        
    )
    submit = SubmitField(label="Submit")
    
    def validate_path(self, path):
        print(path.data)
        try:
            parse_secret_path(path.data)
        except KvAccessError:
            raise ValidationError("Path is invalid")
        