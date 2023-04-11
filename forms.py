from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Length, Regexp
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20, message="Username must be between 4 and 20 characters long."),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, or underscores.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=4, max=20, message="Password must be between 4 and 20 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message="Passwords must match.")
    ])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=4, max=20, message="Username must be between 4 and 20 characters long."),
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers, or underscores.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=4, max=20, message="Password must be between 4 and 20 characters long.")
    ])
    submit = SubmitField('Login')

    def validate_password(self, password):
        user = User.query.filter_by(username=self.username.data).first()
        if not user or not user.check_password(password.data):
            raise ValidationError('Username or password is incorrect. Please try again.')

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[
        DataRequired(message="Title is required."),
        Length(max=100, message="Title must be no more than 100 characters long.")
    ])
    content = TextAreaField('Content', validators=[
        DataRequired(message="Content is required."),
        Length(max=5000, message="Title must be no more than 5000 characters long.")
        ])
    category = StringField('Category', validators=[
        Length(max=50, message="Category must be no more than 50 characters long.")
    ])
    submit = SubmitField('Save Note')


