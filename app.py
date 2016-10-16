# ----------------------------------------------------------------------------#
# Imports
# ----------------------------------------------------------------------------#

from flask import Flask, render_template, flash, jsonify
from flask import url_for, redirect
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import flask_excel as excel
from flask_wtf.csrf import CsrfProtect
import logging
from logging import Formatter, FileHandler
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from pyinvoice.models import InvoiceInfo, ClientInfo, Item, ServiceProviderInfo
from pyinvoice.templates import SimpleInvoice
from flask import request
import json, os, urllib, requests
from flask_mail import Mail, Message
from flask_paginate import Pagination
from flask_migrate import Migrate

# ----------------------------------------------------------------------------#
# App Config.
# ----------------------------------------------------------------------------#
app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

from models import *
from forms import *
from paymentFunctions import stripe_payment

csrf = CsrfProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
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
  api_key = request.args.get('api_key')
  if api_key:
    user = Business.query.filter_by(api_key=api_key).first()
    if user:
      return user

  token = request.headers.get('Authorization')
  if token is None:
    token = request.args.get('token')

  if token is not None:
    username, password = token.split(":")
    user_entry = Business.get(username)
    if (user_entry is not None):
      user = Business(user_entry[0], user_entry[1])
      if (user.password == password):
        return user
  return None


@login_manager.user_loader
def load_user(id):
  if id is None or id == 'None':
    id = -1
  return Business.query.get(int(id))

'''
# ----------------------------------------------------------------------------#
# payment specific controllers.
# ----------------------------------------------------------------------------#
'''

@csrf.exempt
@app.route('/stripeCharge', methods=['POST', 'GET'])
@login_required
def stripe_charge():
  if request.form:
    stripe_token = request.form.get('stripeToken')
    stripe_email = request.form.get('stripeEmail')
    connected_user_id = current_user.stripeUserId
    amount = request.form.get('invoiceAmt')
    try:
      stripe_payment(stripe_token, stripe_email, connected_user_id, amount)
    except Exception as e:
      print(repr(e))
      return render_template('error.html', error=repr(e))
    return render_template('pages/paymentSuccess.html', payment_amount=str(amount),
                           connected_account_id=connected_user_id,
                           connected_account_email=stripe_email)
  return redirect(url_for('home'))

@app.route('/stripePayment', methods=["GET", "POST"])
@login_required
def stripe_payment_form():
  invoiceId = request.args['invoiceId']
  invoice = Invoice.query.filter_by(id=invoiceId).first()
  return render_template('pages/stripePayment.html', key=app.config['STRIPE_PUBLISHABLE_KEY'], invoice=invoice)


@app.route('/authorize')
@login_required
def stripe_authorize():
  site = "https://connect.stripe.com/oauth/authorize"
  params = {
    "response_type": "code",
    "scope": "read_write",
    "client_id": app.config['STRIPE_CLIENT_ID']
  }
  url = site + '?' + urllib.urlencode(params)
  return redirect(url)


@app.route('/oauth/callback')
@login_required
def stripe_callback():
  code = request.args.get('code')
  data = {
    "grant_type": "authorization_code",
    "client_id": app.config['STRIPE_CLIENT_ID'],
    "client_secret": app.config['STRIPE_SECRET_KEY'],
    "code": code
  }
  url = "https://connect.stripe.com/oauth/token"
  resp = requests.post(url, params=data)
  token = resp.json().get('access_token')
  clientStripeUserId = resp.json().get('stripe_user_id')
  user = db.session.query(Business).get(current_user.id)
  user.stripeUserId = clientStripeUserId
  user.stripeToken = token
  db.session.commit()
  flash('Your Stripe account is now set up. We will send payment links alongwith the invoice mails to your clients',
        'success')
  return redirect(url_for('home'))


'''
# ----------------------------------------------------------------------------#
# idea specific controllers.
# ----------------------------------------------------------------------------#
'''

@csrf.exempt
@app.route("/createInvoice", methods=['GET', 'POST'])
@login_required
def create_invoice():
  form = CreateLineInvoice(request.form)
  if form.validate_on_submit():
    invoiceAmt = str(float(form.data['unitCount'])*float(form.data['unitPrice']))
    line = [form.data['invoiceNumber'], form.data['clientName'], form.data['clientEmail'], form.data['clientPhone'],form.data['itemSummary'],
            form.data['description'], form.data['invoiceDueDate'], form.data['unitCount'], form.data['unitPrice'],invoiceAmt]
    print line
    invoice = createLineInvoice(line, current_user)
    db.session.add(invoice)
    db.session.commit()
    invoiceDict = {}
    invoiceDict['invoice' + str(invoice.id) + '.pdf'] = invoice
    returnedInvoiceDict = sendMail(invoiceDict,False)
    return redirect(url_for('display_result', result=json.dumps(returnedInvoiceDict)))
  if request.method == 'POST':
    excelContent = request.get_array(field_name='file')
    header = [str(x) for x in excelContent[0]]
    line = ["Invoice Number","Client Name","Client Email","Client Phone","Item Summary","Item Description",
            "Invoice Due Date","Unit Count","Unit Price"]
    if (header == line):
      invoiceDict = createInvoice(excelContent, current_user)
      returnedInvoiceDict = sendMail(invoiceDict,False)
      return redirect(url_for('display_result', result=json.dumps(returnedInvoiceDict)))
    else:
      print header
      flash("Correct your column order to the following - 'Invoice Number','Client Name','Client Email','Client Phone','Item Summary','Item Description','Invoice Due Date','Unit Count','Unit Price'")
  return render_template('forms/createInvoice.html', form=form)


@csrf.exempt
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
@login_required
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


'''
# ----------------------------------------------------------------------------#
# Login,registration and other common controllers.
# ----------------------------------------------------------------------------#
'''


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
  return redirect(url_for('index_supplier'))


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
    flash('A confirmation email has been sent. Please check your inbox', 'success')
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
    # db.session.add(user)
    # db.session.commit()
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
      print "HI" + recovery_url
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

@app.route('/supplier', methods=["GET", "POST"])
def index_supplier():
  return render_template('pages/indexSupplier.html')

@app.route('/enterprise', methods=["GET", "POST"])
def index_enterprise():
  form = RequestDemo(request.form)
  if form.validate_on_submit():
    enterprise = Business("", "", form.data['email'], "", form.data['phone'])
    db.session.add(enterprise)
    db.session.commit()
    flash("Thanks for your interest! We'll be in touch soon.", 'success')
  return render_template('pages/indexEnterprise.html', form=form)

@app.route('/requestDemo', methods=["GET", "POST"])
def request_demo():
  form = RequestDemo(request.form)
  if form.validate_on_submit():
    enterprise = Business("", "",form.data['email'],"", form.data['phone'])
    db.session.add(enterprise)
    db.session.commit()
    flash("Thanks for your interest! We'll be in touch soon", 'success')
    #return redirect(url_for("login"))
  return render_template('forms/requestDemo.html', form=form)

@app.route('/', methods=["GET", "POST"])
def index():
  return redirect(url_for('index_enterprise'))

@app.route('/ycdemo', methods=["GET", "POST"])
def ycdemo():
  user = Business.query.filter_by(email='yc@yc.com').first()
  login_user(user, remember=True)
  return redirect(request.args.get('next') or url_for('home'))


@app.route('/about')
def about():
  return render_template('pages/indexSupplier.html')


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
# Site functions
# ----------------------------------------------------------------------------#

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
# product specific functions
# ----------------------------------------------------------------------------#


def sendMail(invoiceDict,isDiscount):
  with mail.connect() as conn:
    invoiceMailDict = {}
    directory = 'static/invoices/' + current_user.name + '/'
    if not os.path.exists(directory):
      os.makedirs(directory)
    for invoicePdf, invoice in invoiceDict.items():
      business = Business.query.filter_by(id=invoice.businessId).first()
      if(isDiscount):
        subject = "Discounted invoice received from %s for $%s" % (business.company, invoice.invoiceAmt)
      else:
        subject = "Invoice received from %s for $%s" % (business.company, invoice.invoiceAmt)
      if current_user.stripeToken is None:
        link = "http://tryscribe.com/stripePayment?invoiceId="+str(invoice.id)
        html = render_template('pages/invoiceMailWithPaymentLink.html', business=business, invoice=invoice,
                               key=app.config['STRIPE_PUBLISHABLE_KEY'], link=link)
      else:
        html = render_template('pages/invoiceMail.html', business=business, invoice=invoice)
      msg = Message(sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[invoice.clientEmail],
                    html=html,
                    subject=subject)
      with app.open_resource(invoicePdf) as fp:
        msg.attach(invoicePdf, "application/pdf", fp.read())
      conn.send(msg)
      os.rename(invoicePdf, directory + invoicePdf)
      invoiceMailDict[invoice.clientEmail] = invoicePdf
  return invoiceMailDict


def send_discount(request):
  discount = request.form['discount']
  invoiceId = request.form['invoiceId']
  invoice = Invoice.query.filter_by(invoiceNumber=str(invoiceId)).first()
  invoiceAmt = str(float(float(invoice.invoiceAmt)) - int(float(invoice.invoiceAmt) * float(discount)*0.01 / 100.0))
  invoiceDueDate = (datetime.today() + timedelta(days=3)).strftime('%d-%m-%y')
  invoiceNew = createLineInvoice(
    [invoice.invoiceNumber + "_discounted", "", invoice.clientEmail, "", invoice.invoiceDesc, "", invoiceDueDate,
     invoice.unitCount, invoice.unitPrice, invoiceAmt], current_user)
  invoiceDict = {}
  invoiceDict['invoice' + str(invoiceNew.id) + '.pdf'] = invoiceNew
  returnedInvoiceDict = sendMail(invoiceDict,discount)
  return returnedInvoiceDict

def createLineInvoice(line, current_user):
  invoiceNumber = str(line[0])
  invoiceDueDate = line[6]
  unitCount = line[7]
  unitPrice = line[8]
  invoiceDesc = line[4]
  clientEmail = line[2]
  clientName = line[1]
  invoiceAmt = line[9]
  invoice = Invoice(invoiceNumber, clientName, clientEmail, current_user.id, unitCount, unitPrice, invoiceAmt, invoiceDueDate, datetime.today().strftime('%d-%m-%y'),
                    invoiceDesc)
  db.session.add(invoice)
  db.session.commit()
  doc = SimpleInvoice('invoice' + str(invoice.id) + '.pdf')
  doc.invoice_info = InvoiceInfo(line[0], datetime.today(),invoiceDueDate)
  business = Business.query.filter_by(id=current_user.id).first()
  doc.service_provider_info = ServiceProviderInfo(
    name=business.name,
    street=business.street,
    city=business.city,
    state=business.state,
  )
  doc.client_info = ClientInfo(email=clientEmail,name=clientName)
  doc.add_item(Item(invoiceDesc, line[5], unitCount, unitPrice))
  doc.finish()
  return invoice


def createInvoice(excelContent, current_user):
  invoiceDict = {}
  for line in excelContent[1:]:
    print line
    line.append(str(float(line[7])*float(line[8])))
    print line
    invoice = createLineInvoice(line, current_user)
    invoiceDict['invoice' + str(invoice.id) + '.pdf'] = invoice
  return invoiceDict

def sendReminder(invoiceDict):
  return

# ----------------------------------------------------------------------------#
# Launch.
# ----------------------------------------------------------------------------#

if __name__ == '__main__':
  port = int(os.environ.get('PORT', 5000))
  app.run(host='0.0.0.0', port=port)  # add debug=False to call teardown_req and delete sessions
  # http_server = WSGIServer(('0.0.0.0', port), app)
  # http_server.serve_forever()
