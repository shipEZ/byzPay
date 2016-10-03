import os
# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))
# Enable debug mode.
DEBUG = True

# Secret key for session management. You can generate random strings here:
# http://clsc.net/tools-old/random-string-generator.php
SECRET_KEY = os.environ['SECRET_KEY']
SECURITY_PASSWORD_SALT = os.environ['SECURITY_PASSWORD_SALT']
# Connect to the database
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'database.db')

#mail settings
MAIL_SERVER='smtp.gmail.com' #smtp.zoho.com
MAIL_PORT = 465
MAIL_USERNAME = 'sachinbhat.as@gmail.com' #hi@tryscribe.com
MAIL_PASSWORD = os.environ['MAIL_PASSWORD'] #sachin99
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# mail accounts
MAIL_DEFAULT_SENDER = 'hi@tryscribe.com'
