from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class OwnershipCheckForm(FlaskForm):
    path = StringField(
        "Secret path",
        validators=[
            DataRequired(message="A secret path is required"),
            Length(max=512, message="Path is too long"),
        ],
    )
    submit = SubmitField("Check ownership")
