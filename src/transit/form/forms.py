from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, SubmitField, TextAreaField, ValidationError
from wtforms.validators import DataRequired, Length
from src.transit.utils import validate_key_name, TransitError

class CreateKeyForm(FlaskForm):
    key_name = StringField(
        "Key Name",
        validators=[
            DataRequired(),
            Length(1,64)],
        )
    submit = SubmitField("Create")
    def validate_key_name(self, key_name):
        try: 
            validate_key_name(key_name.data)
        except TransitError:
            raise ValidationError("Invalid key name. Key name may only include letters, numbers, dot, dash, or underscore ")
            
class CreateSignKeyForm(FlaskForm):
    key_name = StringField(
        "Key Name",
        validators=[
            DataRequired(),
            Length(1,64)],
        )
    
    submit = SubmitField("Create")
    def validate_key_name(self, key_name):
        try: 
            validate_key_name(key_name.data)
        except TransitError:
            raise ValidationError("Invalid key name. Key name may only include letters, numbers, dot, dash, or underscore ")
            

class EncryptForm(FlaskForm):
    key_name = SelectField(
        "Named encryption key",
        choices=[],
        validators=[DataRequired(message="Select a named key")],
    )
    input_format = SelectField(
        "Input format",
        choices=[("text", "UTF-8 text"), ("base64", "Base64")],
        default="text",
        validators=[DataRequired()],
    )
    plaintext = TextAreaField(
        "Plaintext",
        validators=[
            DataRequired(message="Plaintext is required"),
            Length(max=1_500_000, message="Plaintext input is too large"),
        ],
    )
    submit = SubmitField("Encrypt")


class DecryptForm(FlaskForm):
    ciphertext = TextAreaField(
        "Vault ciphertext",
        validators=[
            DataRequired(message="Ciphertext is required"),
            Length(max=2_000_000, message="Ciphertext input is too large"),
        ],
    )
    submit = SubmitField("Decrypt")


class BootstrapKeyForm(FlaskForm):
    key_name = StringField(
        "Demo key name",
        default="demo-key",
        validators=[DataRequired(), Length(max=64)],
    )
    submit = SubmitField("Create temporary demo key")
