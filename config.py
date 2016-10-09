import os
# Grabs the folder where the script runs.
basedir = os.path.abspath(os.path.dirname(__file__))
# Enable debug mode.
DEBUG = True


SECRET_KEY = os.environ['SECRET_KEY']
SECURITY_PASSWORD_SALT = os.environ['SECURITY_PASSWORD_SALT']
# Connect to the database
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'database.db')

#mail settings
MAIL_SERVER='smtp.gmail.com'
MAIL_PORT = 465
MAIL_USERNAME = 'hi@tryscribe.com'
MAIL_PASSWORD =  os.environ['MAIL_PASSWORD']
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# mail accounts
MAIL_DEFAULT_SENDER = 'hi@tryscribe.com'

# Stripe test configs
STRIPE_CLIENT_ID = 'ca_9KNKL89g9NkEqU0sunL2HuVZGSLdiBPD'
STRIPE_SECRET_KEY = 'sk_test_J1C47kLMolxuraaz86eB3iYX'
STRIPE_PUBLISHABLE_KEY = 'pk_test_dzO4Vz93tvnyjdYOxHEvBsQp'


#CSS color schemas
#1 lavendarish = #4ACCD1;
#2 color = #3fbbc0;
#3 Default = #4ACCD1;
#4 orage = #FA482A

