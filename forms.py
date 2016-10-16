from flask_wtf import Form
from wtforms import TextField, PasswordField, IntegerField, DateField
from wtforms.validators import DataRequired, EqualTo, Length, Email, ValidationError
from wtforms import validators
from wtforms.fields.html5 import EmailField
from models import *

# Set your classes here.

class RegisterBusiness(Form):
    name = TextField(
        'Name', validators=[DataRequired(message="Please enter your name"), Length(min=1, max=25)]
    )
    company = TextField(
        'Company', validators=[DataRequired("Please enter your company name"), Length(min=1, max=50)]
    )
    email = EmailField(
        'Email', validators=[DataRequired(message="Please enter your email address"), validators.Email("Please enter correct email address.")]
    )
    password = PasswordField(
        'Password', validators=[DataRequired(), Length(min=2, max=40)]
    )
    phone = IntegerField(
        'Phone', validators=[DataRequired(message="Please enter your phone number")]
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
    vatTaxNo = IntegerField(
        'VAT Number', validators=[Length(min=6, max=40)]
    )
    #Add logo upload option later


class CreateLineInvoice(Form):
    invoiceNumber = TextField(
        'Invoice No', validators=[DataRequired(message="Please enter the invoice number"), Length(min=1, max=25)]
    )
    clientName = TextField(
        'Client Name', validators=[DataRequired("Please enter client's name"), Length(min=1, max=50)]
    )
    clientEmail = EmailField(
        'Client Email', validators=[DataRequired(message="Please enter client's email"), Length(min=1, max=50), validators.Email("Please enter correct email address.")]
    )
    clientPhone = IntegerField(
        'Client Phone', validators=[DataRequired(message="Please enter your phone number")]
    )
    itemSummary = TextField(
        'Item Summary', validators=[DataRequired("Please enter item summary"), Length(min=1, max=50)]
    )
    description = TextField(
        'Item Description', validators=[Length(min=1, max=50)]
    )
    invoiceDueDate = TextField(
        'Invoice Due Date', validators=[DataRequired("Please enter invoice due date"), Length(min=1, max=50)]
    )
    unitCount = TextField(
        'Unit Count', validators=[DataRequired("Please enter number of units"), Length(min=1, max=50)]
    )
    unitPrice = TextField(
        'Unit Price', validators=[DataRequired("Please enter unit price"), Length(min=1, max=50)]
    )

class LoginForm(Form):
    email = TextField('Email', [DataRequired(), validators.Email("Please enter correct email address.")])
    password = PasswordField('Password', [DataRequired()])


class ForgotForm(Form):
    email = TextField(
        'Email', validators=[DataRequired(), Length(min=6, max=40), validators.Email("Please enter correct email address.")]
    )

class ResetPasswordSubmit(Form):
    password = PasswordField('Password', validators=[validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')


class RequestDemo(Form):
    email = EmailField(
        'Email', validators=[DataRequired(message="Please enter your email address"),
                                validators.Email("Please enter correct email address.")]
    )
    phone = IntegerField(
        'Phone', validators=[DataRequired(message="Please enter your phone number")]
    )