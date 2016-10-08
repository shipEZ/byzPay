#Generic flask site functions

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
import json, os, bcrypt, urllib, requests
from flask_mail import Mail, Message
from flask_paginate import Pagination
from flask_migrate import Migrate
import stripe

from app import app, db
mail = Mail(app)



