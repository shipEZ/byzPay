#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, render_template, flash, jsonify
from flask import url_for, redirect
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CsrfProtect
import logging
from logging import Formatter, FileHandler
from forms import *
from models import *
from invoice import *
from datetime import datetime, date
from pyinvoice.models import InvoiceInfo, ServiceProviderInfo, ClientInfo, Item, Transaction
from pyinvoice.templates import SimpleInvoice
import flask_excel as excel
from flask import request
import json, os, bcrypt
from flask_mail import Mail, Message
from flask_paginate import Pagination

#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#

app = Flask(__name__)
app.config.from_object('config')
#app.config['SQLALCHEMY_ECHO'] = True #for debug purposes. tbd
db = SQLAlchemy(app)
csrf = CsrfProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login" #default view to redirect from login_required if not logged in i.e
mail = Mail(app)

# Automatically tear down SQLAlchemy.
'''
@app.teardown_request
def shutdown_session(exception=None):
    print "sachin"
    db_session.remove()
'''

@login_manager.request_loader
def load_user(request):
    # first, try to login using the api_key url arg
    api_key = request.args.get('api_key')
    if api_key:
        user = Business.query.filter_by(api_key=api_key).first()
        if user:
            return user

    token = request.headers.get('Authorization')
    if token is None:
        token = request.args.get('token')

    if token is not None:
        username,password = token.split(":") # naive token
        user_entry = Business.get(username)
        if (user_entry is not None):
            user = Business(user_entry[0],user_entry[1])
            if (user.password == password):
                return user
    return None

@login_manager.user_loader
def load_user(id):
    """Given *user_id*, return the associated User object.
    :param unicode user_id: user_id (email) user to retrieve
    """
    return Business.query.get(int(id))

def createInvoice(excelContent, current_user):
    invoiceDict={}
    for line in excelContent[1:]:
        invoiceNumber=str(line[0])
        InvoiceDueDate = line[6]
        invoiceAmt = line[7]
        invoiceDesc = line[4] #invoiceSummary i.e
        doc = SimpleInvoice('invoice'+invoiceNumber+'.pdf')
        doc.invoice_info = InvoiceInfo(line[0], datetime.now(), InvoiceDueDate)  # Invoice info - id, invoice date, invoice due date
        clientEmail = line[2]
        doc.client_info = ClientInfo(email=clientEmail)
        doc.add_item(Item(invoiceDesc,line[5],invoiceAmt,'0'))
        invoiceDict['invoice'+str(line[0])+'.pdf']=clientEmail
        invoice = Invoice(invoiceNumber,clientEmail,current_user.id, invoiceAmt, InvoiceDueDate,datetime.now(),invoiceDesc)
        db.session.add(invoice)
        db.session.commit()
        doc.finish()
    return invoiceDict

def sendMail(invoiceDict):
    with mail.connect() as conn:
        invoiceMailDict={}
        directory='static/invoices/'+current_user.name+'/'
        if not os.path.exists(directory):
            os.makedirs(directory)
        for invoice,email in invoiceDict.items():
            message = 'Kindly pay them to the following bank account 000000000'
            subject = "An invoice is due." #"hello, %s" % user.name
            msg = Message(sender = 'hi@tryscribe.com',
                          recipients=[email],
                          body=message,
                          subject=subject)
            with app.open_resource(invoice) as fp:
                msg.attach(invoice, "application/pdf", fp.read())
            conn.send(msg)
            os.rename(invoice,directory+invoice)
            invoiceMailDict[email]=invoice
    return invoiceMailDict

def setSearchOption(request):
    search = False
    q = request.args.get('q')
    if q:
        search = True
    return search
#----------------------------------------------------------------------------#
# idea specific controllers.
#----------------------------------------------------------------------------#

@csrf.exempt
@app.route("/uploadFile", methods=['GET', 'POST'])
def create_invoice():
    if request.method == 'POST':
        excelContent = request.get_array(field_name='file')
        invoiceDict = createInvoice(excelContent,current_user)
        returnedInvoiceDict = sendMail(invoiceDict)
        return redirect(url_for('display_result',result=json.dumps(returnedInvoiceDict)))
    return render_template('forms/uploadFile.html')

@app.route("/displayResult", methods=['GET', 'POST'])
@login_required
def display_result():
    returnedResult = request.args['result']
    if(returnedResult is not None):
        result = json.loads(str(returnedResult))
        page = request.args.get('page', type=int, default=1)
        search = setSearchOption(request)
        pagination = Pagination(page=page, total=len(result), search=search, record_name='result')
        return render_template("pages/printResult.html", result=result, pagination=pagination)
    else:
        return redirect(url_for('home'))

@app.route("/dynamicDiscounting", methods=['GET', 'POST'])
@login_required
def dynamic_discounting():
    invoices = Invoice.query.filter_by(businessId=current_user.id)
    page = request.args.get('page', type=int, default=1)
    search = setSearchOption(request)
    pagination = Pagination(page=page, total=invoices.count(), search=search, record_name='invoices')
    return render_template('pages/dynamicDiscounting.html',invoices=invoices,pagination=pagination)
#----------------------------------------------------------------------------#
# Login,registration and other common controllers.
#----------------------------------------------------------------------------#

@app.route('/createBusiness', methods=["GET","POST"])
def create_business():
    form = RegisterBusiness(request.form)
    if form.validate_on_submit():
        user = Business(form.data['name'],form.data['company'],form.data['email'],form.data['password'],
                                form.data['phone'])
        db.session.add(user)
        db.session.commit()
        flash('User successfully registered')
        return redirect(url_for('login', user=user))
    else:
        print form.errors
        flash('Error. Please try again!')
    return render_template('forms/createBusiness.html', form=form)

@app.route('/updateBusinessDetails', methods=["GET","POST"])
@login_required
def update_business_details():
    form = UpdateBusinessDetails(request.form)
    if form.validate_on_submit():
        updates={'street':form.data['street'],'city':form.data['city'],'state':form.data['state'],'country':form.data['country'],
                 'zipcode':form.data['zipCode'],'vatno':form.data['vatTaxNo']}
        for k,v in updates:
            print k,v
            setattr(current_user,k,v)
        db.session.commit()
        return redirect(url_for('create_invoice'))
    #else:
    #    flash('please enter correct details')
    return render_template('forms/updateBusinessDetails.html', form=form)

@app.route('/login', methods=["GET","POST"])
def login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = Business.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.hashpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')) == user.password.encode('utf-8'):
                login_user(user, remember=True)
                return redirect(request.args.get('next') or url_for('create_invoice'))
            else:
                flash('Username or Password is invalid', 'error')
                return redirect(url_for('login'))
        else:
            flash('Username or Password is invalid', 'error')
            return redirect(url_for('login'))
    return render_template("forms/login.html", form=form)

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    print current_user
    logout_user()
    return redirect(url_for('index'))

@app.route('/forgotPassword')
def forgot_password():
    form = ForgotForm(request.form)
    return render_template('forms/forgot.html', form=form)

@app.route('/',methods=["GET","POST"])
def home():
    return render_template('pages/index.html')

@app.route('/', methods=["GET","POST"])
def index():
    return render_template('pages/index.html')

@app.route('/about')
def about():
    return render_template('pages/index.html')

@app.route('/register')
def register():
    return redirect(url_for('create_business'))




# Error handlers.
@app.errorhandler(500)
def internal_error(error):
    #db_session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setFormatter(
        Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('errors')

#----------------------------------------------------------------------------#
# Launch.
#----------------------------------------------------------------------------#

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port) #add debug=False to call teardown_req and delete sessions
