#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, render_template, request, flash, jsonify
from flask import url_for, redirect
from flask.ext.login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask.ext.sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CsrfProtect
import logging
from logging import Formatter, FileHandler
from forms import *
from models import *
from invoice import *
import os, bcrypt
import flask_excel as excel
from flask_mail import Mail, Message

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


def sendMail(invoiceDict):
    with mail.connect() as conn:
        for invoice,email in invoiceDict.items():
            print invoice, email
            message = 'Kindly pay them to the following bank account 000000000'
            subject = "An invoice is due." #"hello, %s" % user.name
            msg = Message(sender = 'sachinbhat.as@gmail.com',
                          recipients=[email],
                          body=message,
                          subject=subject)
            with app.open_resource(invoice) as fp:
                msg.attach(invoice, "application/pdf", fp.read())
            print "mail sent to "+email
            conn.send(msg)

#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#

@app.route('/createBusiness', methods=["GET","POST"])
def createBusiness():
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
def updateBusinessDetails():
    form = UpdateBusinessDetails(request.form)
    if form.validate_on_submit():
        user = Business(form.data['name'], form.data['company'], form.data['email'], form.data['password'],
                            form.data['phone'])
        return redirect(url_for('uploadFile', user=user))
    else:
        flash('wrong username/password')
    return render_template('forms/createBusiness.html', form=form)

@app.route('/login', methods=["GET","POST"])
def login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = Business.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.hashpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')) == user.password.encode('utf-8'):
                login_user(user, remember=True)
                return redirect(request.args.get('next') or url_for('uploadFile'))
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
    print "hail mary"
    print current_user
    logout_user()
    return redirect(url_for('index'))

@app.route('/forgotPassword')
def forgotPassword():
    form = ForgotForm(request.form)
    return render_template('forms/forgot.html', form=form)

@csrf.exempt
@app.route("/uploadFile", methods=['GET', 'POST'])
def uploadFile():
    user = request.args.get('user')
    if request.method == 'POST':
        excelContent = request.get_array(field_name='file')
        invoiceDict = createInvoice(excelContent)
        sendMail(invoiceDict)
        excelFile = jsonify({"result": excelContent})
        print excelFile
        return excelFile
    return render_template('forms/uploadFile.html')

#preset routes. TBD
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
    return redirect(url_for('createBusiness'))
    form = ForgotForm(request.form)
    return render_template('pages/register.html', form=form)




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
