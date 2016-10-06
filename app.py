# ----------------------------------------------------------------------------#
# Imports
# ----------------------------------------------------------------------------#

from flask import Flask, render_template, flash, jsonify
from flask import url_for, redirect
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CsrfProtect
import logging
from logging import Formatter, FileHandler
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, date, timedelta
from pyinvoice.models import InvoiceInfo, ServiceProviderInfo, ClientInfo, Item, Transaction
from pyinvoice.templates import SimpleInvoice
import flask_excel as excel
from flask import request
import json, os, bcrypt
from flask_mail import Mail, Message
from flask_paginate import Pagination

from forms import *
from models import *
from productSpecificFunctions import *

# ----------------------------------------------------------------------------#
# App Config.
# ----------------------------------------------------------------------------#

app = Flask(__name__)
app.config.from_object('config')
# app.config['SQLALCHEMY_ECHO'] = True #for debug purposes. tbd
db = SQLAlchemy(app)
csrf = CsrfProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # default view to redirect from login_required if not logged in i.e
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
    username, password = token.split(":")  # naive token
    user_entry = Business.get(username)
    if (user_entry is not None):
      user = Business(user_entry[0], user_entry[1])
      if (user.password == password):
        return user
  return None


@login_manager.user_loader
def load_user(id):
  """Given *user_id*, return the associated User object.
  :param unicode user_id: user_id (email) user to retrieve
  """
  if id is None or id == 'None':
    id = -1
  return Business.query.get(int(id))

def createLineInvoice(line, current_user):
  invoiceNumber = str(line[0])
  invoiceDueDate = line[6]
  invoiceAmt = line[7]
  invoiceDesc = line[4]  # invoiceSummary i.e
  clientEmail = line[2]
  invoice = Invoice(invoiceNumber, clientEmail, current_user.id, invoiceAmt, invoiceDueDate, datetime.now(),
                    invoiceDesc)
  db.session.add(invoice)
  db.session.commit()
  doc = SimpleInvoice('invoice' + str(invoice.id) + '.pdf')
  doc.invoice_info = InvoiceInfo(line[0], datetime.now(),invoiceDueDate)
  doc.client_info = ClientInfo(email=clientEmail)
  doc.add_item(Item(invoiceDesc, line[5], invoiceAmt, '0'))
  doc.finish()
  return invoice


def createInvoice(excelContent, current_user):
  invoiceDict = {}
  for line in excelContent[1:]:
    invoice = createLineInvoice(line, current_user)
    invoiceDict['invoice' + str(invoice.id) + '.pdf'] = invoice
  return invoiceDict

def sendReminder(invoiceDict):
  return

def sendMail(invoiceDict):
  with mail.connect() as conn:
    invoiceMailDict = {}
    directory = 'static/invoices/' + current_user.name + '/'
    if not os.path.exists(directory):
      os.makedirs(directory)
    for invoicePdf, invoice in invoiceDict.items():
      business = Business.query.filter_by(id=invoice.businessId).first()
      message = "You've received an invoice from %s at %s for a total amount of $ %s. " \
                "Please pay this invoice by the due date of %s. " \
                "Contact %s directly at %s or via email at %s for any questions." % (
                business.name, business.company, invoice.invoiceAmt, invoice.invoiceDueDate, business.name,
                business.phone, business.email)
      html = render_template('pages/invoiceMail.html', business=business, invoice=invoice)
      subject = "Invoice received from %s for $%s" % (business.company, invoice.invoiceAmt)
      msg = Message(sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[invoice.clientEmail],
                    html=html,
                    subject=subject)
      with app.open_resource(invoicePdf) as fp:
        msg.attach(invoicePdf, "application/pdf", fp.read())
      conn.send(msg)
      os.rename(invoicePdf, directory + invoicePdf)
      print invoicePdf
      invoiceMailDict[invoice.clientEmail] = invoicePdf
  return invoiceMailDict


def send_discount(request):
  discount = request.form['discount']
  invoiceId = request.form['invoiceId']
  print discount
  print invoiceId
  invoice = Invoice.query.filter_by(invoiceNumber=str(invoiceId)).first()
  invoiceAmt = str(int(float(invoice.invoiceAmt)) - int(float(invoice.invoiceAmt) * float(discount) / 100.0))
  invoiceDueDate = datetime.today() + timedelta(days=30)
  invoiceNew = createLineInvoice(
    [invoice.invoiceNumber + "_discounted", "", invoice.clientEmail, "", invoice.invoiceDesc, "", invoiceDueDate,
     invoiceAmt], current_user)
  invoiceDict = {}
  invoiceDict['invoice' + str(invoiceNew.id) + '.pdf'] = invoiceNew
  returnedInvoiceDict = sendMail(invoiceDict)
  return returnedInvoiceDict

def sendConfirmationMail(to, subject, template):
  msg = Message(
    subject,
    recipients=[to],
    html=template,
    sender=app.config['MAIL_DEFAULT_SENDER']
  )
  mail.send(msg)


def generate_confirmation_token(email):
  serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
  return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
  serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
  try:
    email = serializer.loads(
      token,
      salt=app.config['SECURITY_PASSWORD_SALT'],
      max_age=expiration
    )
  except:
    return False
  return email


def setSearchOption(request):
  search = False
  q = request.args.get('q')
  if q:
    search = True
  return search


def redirect_url(default='index'):
  return request.args.get('next') or \
         request.referrer or \
         url_for(default)


# ----------------------------------------------------------------------------#
# idea specific controllers.
# ----------------------------------------------------------------------------#

@csrf.exempt
@app.route("/uploadFile", methods=['GET', 'POST'])
def create_invoice():
  if request.method == 'POST':
    excelContent = request.get_array(field_name='file')
    header=[str(x) for x in excelContent[0]]
    line=["Invoice Number","Client Name","Client Email","Client Phone","Item Summary","Item Description","Invoice Due Date","Invoice Amount"]
    if(header==line):
      invoiceDict = createInvoice(excelContent, current_user)
      returnedInvoiceDict = sendMail(invoiceDict)
      return redirect(url_for('display_result', result=json.dumps(returnedInvoiceDict)))
    else:
      print header
      flash("Correct your column order to the following - invoice no,client name,client email,client phone,item summary,item description,due date,invoice amount")
  return render_template('forms/uploadFile.html')

@csrf.exempt
@app.route("/createLineInvoice", methods=['GET', 'POST'])
def create_invoice_via_form():
  form = CreateLineInvoice(request.form)
  if form.validate_on_submit():
    line = [form.data['invoiceNumber'], form.data['clientName'], form.data['clientEmail'], form.data['clientPhone'],
            form.data['itemSummary'], form.data['description'], form.data['invoiceDueDate'], form.data['invoiceAmt']]
    invoice = createLineInvoice(line, current_user)
    db.session.add(invoice)
    db.session.commit()
    invoiceDict={}
    invoiceDict['invoice' + str(line[0]) + '.pdf'] = invoice
    returnedInvoiceDict = sendMail(invoiceDict)
    return redirect(url_for('display_result', result=json.dumps(returnedInvoiceDict)))
  return render_template('forms/createLineInvoice.html',form=form)


@app.route("/displayResult", methods=['GET', 'POST'])
@login_required
def display_result():
  returnedResult = request.args['result']
  if (returnedResult is not None):
    result = json.loads(str(returnedResult))
    print result
    page = request.args.get('page', type=int, default=1)
    search = setSearchOption(request)
    pagination = Pagination(page=page, total=len(result), search=search, record_name='result')
    return render_template("pages/printResult.html", result=result, pagination=pagination)
  else:
    return redirect(url_for('home'))


@csrf.exempt
@app.route("/dynamicDiscounting", methods=['GET', 'POST'])
def dynamic_discounting():
  if request.method == 'POST':
    returnedInvoiceDict = send_discount(request)
    flash("we sent the new invoice to the client", "success")
  invoices = Invoice.query.filter_by(businessId=current_user.id)
  page = request.args.get('page', type=int, default=1)
  search = setSearchOption(request)
  ITEMS_PER_PAGE = 10
  i = (page - 1) * ITEMS_PER_PAGE
  invoicesPerPage = invoices[i:i + ITEMS_PER_PAGE]
  pagination = Pagination(page=page, per_page=10, total=invoices.count(), search=search, record_name='invoices',
                          css_framework='bootstrap3')
  return render_template('pages/dynamicDiscounting.html', title='Discounts!!', invoices=invoicesPerPage,
                         pagination=pagination)

@app.route("/sentInvoices", methods=['GET', 'POST'])
def sent_invoices():
  invoices = Invoice.query.filter_by(businessId=current_user.id)
  page = request.args.get('page', type=int, default=1)
  search = setSearchOption(request)
  ITEMS_PER_PAGE = 10
  i = (page - 1) * ITEMS_PER_PAGE
  invoicesPerPage = invoices[i:i + ITEMS_PER_PAGE]
  pagination = Pagination(page=page, per_page=10, total=invoices.count(), search=search, record_name='invoices',
                          css_framework='bootstrap3')
  return render_template('pages/sentInvoices.html', invoices=invoicesPerPage,
                         pagination=pagination)

# ----------------------------------------------------------------------------#
# Login,registration and other common controllers.
# ----------------------------------------------------------------------------#

@app.route('/login', methods=["GET", "POST"])
def login():
  form = LoginForm(request.form)
  if form.validate_on_submit():
    user = Business.query.filter_by(email=form.email.data).first()
    if user:
      if bcrypt.hashpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')) == user.password.encode(
          'utf-8'):
        login_user(user, remember=True)
        return redirect(request.args.get('next') or url_for('home'))
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

@app.route('/createBusiness', methods=["GET", "POST"])
def create_business():
  form = RegisterBusiness(request.form)
  if form.validate_on_submit():
    user = Business(form.data['name'], form.data['company'], form.data['email'], form.data['password'],
                    form.data['phone'])
    db.session.add(user)
    db.session.commit()
    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('pages/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    sendConfirmationMail(user.email, subject, html)
    login_user(user)
    flash('A confirmation email has been sent via email.', 'success')
    return redirect(url_for("login"))
  # else:
  #    flash('Error. Please try again!')
  return render_template('forms/createBusiness.html', form=form)


@app.route('/updateBusinessDetails', methods=["GET", "POST"])
@login_required
def update_business_details():
  form = UpdateBusinessDetails(request.form)
  if form.validate_on_submit():
    updates = {'street': form.data['street'], 'city': form.data['city'], 'state': form.data['state'],
               'country': form.data['country'],
               'zipcode': form.data['zipCode'], 'vatno': form.data['vatTaxNo']}
    for k, v in updates:
      print k, v
      setattr(current_user, k, v)
    db.session.commit()
    return redirect(url_for('create_invoice'))
  # else:
  #    flash('please enter correct details')
  return render_template('forms/updateBusinessDetails.html', form=form)

@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
  try:
    email = confirm_token(token)
  except:
    flash('The confirmation link is invalid or has expired.', 'danger')
  user = Business.query.filter_by(email=email).first()
  if user.authenticated:
    flash('Account already confirmed. Please login.', 'success')
  else:
    user.authenticated = True
    # db.session.add(user)
    # db.session.commit()
    flash('You have confirmed your account. Thanks!', 'success')
  return redirect(url_for('home'))

@app.route('/resetPassword/<token>', methods=["GET", "POST"])
def reset_password(token):
    try:
        email = confirm_token(token)
    except:
      flash('The recovery link is invalid or has expired.', 'danger')

    form = ResetPasswordSubmit(request.form)
    if form.validate_on_submit():
        user = Business.query.filter_by(email=email).first()
        user.password = form.password.data
        #db.session.add(user)
        #db.session.commit()
        return redirect(url_for('login'))
    return render_template('forms/resetPassword.html', form=form, token=token)

@app.route('/forgotPassword', methods=["GET", "POST"])
def forgot_password():
  token = request.args.get('token', None)
  form = ForgotForm(request.form)
  if form.validate_on_submit():
    email = form.email.data
    user = Business.query.filter_by(email=email).first()
    if user:
      token = generate_confirmation_token(user.email)
      recovery_url = url_for('reset_password', token=token, _external=True)
      print "HI"+recovery_url
      html = render_template('pages/recover.html', recovery_url=recovery_url)
      subject = "Password reset requested"
      sendConfirmationMail(user.email, subject, html)
      flash('An email has been sent with link to reset password.', 'success')
      return redirect(url_for("login"))
  return render_template('forms/forgot.html', form=form)


@app.route('/home', methods=["GET", "POST"])
@login_required
def home():
  return render_template('pages/home.html')


@app.route('/', methods=["GET", "POST"])
def index():
  return render_template('pages/index.html')

@app.route('/ycdemo', methods=["GET", "POST"])
def ycdemo():
  user = Business.query.filter_by(email='YC@YC.com').first()
  login_user(user, remember=True)
  return redirect(request.args.get('next') or url_for('home'))

@app.route('/about')
def about():
  return render_template('pages/index.html')


@app.route('/register')
def register():
  return redirect(url_for('create_business'))


# Error handlers.
@app.errorhandler(500)
def internal_error(error):
  # db_session.rollback()
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

# ----------------------------------------------------------------------------#
# Launch.
# ----------------------------------------------------------------------------#

if __name__ == '__main__':
  port = int(os.environ.get('PORT', 5000))
  app.run(host='0.0.0.0', port=port)  # add debug=False to call teardown_req and delete sessions
  # http_server = WSGIServer(('0.0.0.0', port), app)
  # http_server.serve_forever()
