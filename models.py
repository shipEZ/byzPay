from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from app import db
import bcrypt
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

engine = create_engine('sqlite:///database.db', echo=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

# Set your classes here.

class Business(Base):
    __tablename__ = 'Business'

    id = db.Column(db.Integer, primary_key=True)
    authenticated = db.Column(db.Boolean, default=True)
    name = db.Column(db.String(120))
    company = db.Column(db.String(120))
    email = db.Column(db.String(120)) #, unique=True)
    password = db.Column(db.String(30))
    phone = db.Column(db.String(120))
    website = db.Column(db.String(120))
    street=db.Column(db.String(120))
    city=db.Column(db.String(120))
    state=db.Column(db.String(120))
    country=db.Column(db.String(120))
    zipCode=db.Column(db.String(120))
    vatTaxNo=db.Column(db.String(120))
    logo=db.Column(db.String(120))
    stripeToken=db.Column(db.String(120))
    stripeUserId=db.Column(db.String(120))

    def __init__(self, name=None, company=None, email=None, password=None, phone=None, website=None,
        street=None, city=None, state=None, country=None, zipCode=None, vatTaxNo=None, logo=None, stripeToken=None,
                 stripeUserId=None, authenticated=False):
        self.name = name
        self.email = email
        self.company = company
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(5).encode('utf-8'))
        self.phone = phone
        self.website = website
        self.street = street
        self.city = city
        self.state = state
        self.country = country
        self.zipCode = zipCode
        self.vatTaxNo = vatTaxNo
        self.logo = logo
        self.stripeToken = None
        self.stripeUserId = None
        self.authenticated = authenticated

    def __repr__(self):
        return "%d/%s/%s" % (self.id, self.name, self.password)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return unicode(self.id)

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return True

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

class Invoice(Base):
    __tablename__ = 'Invoices'

    id = db.Column(db.Integer, primary_key=True)
    invoiceNumber = db.Column(db.String(120))
    clientName =  db.Column(db.String(120))
    clientEmail = db.Column(db.String(120))
    businessId = db.Column(db.String(30))
    invoiceAmt = db.Column(db.String(30))
    invoiceDueDate = db.Column(db.String(30))
    invoiceDate = db.Column(db.String(30))
    invoiceDesc = db.Column(db.String(30))
    invoiceOpened = db.Column(db.Boolean, default=False)
    invoicePaid = db.Column(db.Boolean, default=False)

    def __init__(self, invoiceNumber=None, clientName = None, clientEmail=None, businessId=None, invoiceAmt=None, invoiceDueDate=None,
                 invoiceDate=None,  invoiceDesc=None, invoiceOpened=False, invoicePaid=False):
        self.invoiceNumber = invoiceNumber
        self.clientName = clientName
        self.clientEmail = clientEmail
        self.businessId = businessId
        self.invoiceAmt = invoiceAmt
        self.invoiceDueDate = invoiceDueDate
        self.invoiceDate = invoiceDate
        self.invoiceDesc = invoiceDesc
        self.invoiceOpened = invoiceOpened
        self.invoicePaid = invoicePaid

    def __repr__(self):
        return "%d/%s/%s/%s" % (self.id, self.clientEmail, self.invoiceAmt, self.invoiceDueDate)

# Create tables.
Base.metadata.create_all(bind=engine)
