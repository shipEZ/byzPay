from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length, Email

# Set your classes here.

class RegisterBusiness(Form):
    name = TextField(
        'Name', validators=[DataRequired(message="Please enter your name"), Length(min=1, max=25)]
    )
    company = TextField(
        'Company', validators=[DataRequired("Please enter your company name"), Length(min=1, max=50)]
    )
    email = TextField(
        'Email id', validators=[DataRequired(message="Please enter your email address")] #limit this to company later
    )
    password = PasswordField(
        'Password', validators=[DataRequired(), Length(min=2, max=40)]
    )
    phone = TextField(
        'phone no', validators=[DataRequired(message="Please enter your phone number"), Length(min=1, max=13)]
    )
    '''
    confirm = PasswordField(
            'Repeat Password',
            [DataRequired(),
            EqualTo('password', message='Passwords must match')]
    )'''

class UpdateBusinessDetails(Form):
    street = TextField(
        'Street', validators=[DataRequired(message="Please enter your street"), Length(min=1, max=25)]
    )
    city = TextField(
        'City', validators=[DataRequired("Please enter your city"), Length(min=1, max=50)]
    )
    state = TextField(
        'State', validators=[DataRequired(message="Please enter your state"), Length(min=1, max=50)] 
    )
    country = TextField(
        'Country', validators=[DataRequired("Please enter your country"), Length(min=1, max=50)]
    )
    zipCode = TextField(
        'Zipcode', validators=[DataRequired("Please enter zipcode"), Length(min=1, max=50)]
    )
    vatTaxNo = TextField(
        'VAT Number', validators=[Length(min=6, max=40)]
    )
    #Add logo upload option later

class LoginForm(Form):
    email = TextField('Email', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])

class ForgotForm(Form):
    email = TextField(
        'Email', validators=[DataRequired(), Length(min=6, max=40)]
    )
