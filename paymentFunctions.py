import stripe
from app import app, db
from models import *

stripe.api_key = app.config['STRIPE_SECRET_KEY']

def stripe_payment(stripe_token,stripe_email,connected_user_id,amount):
  stripe.Charge.create(
    amount=amount,
    currency='usd',
    source=stripe_token,
    stripe_account=connected_user_id,
    application_fee=0.1,
  )
  '''
    # Check if there is a Customer already created for this email
    platform_account_customers = stripe.Customer.list()
    platform_customer = [cus for cus in platform_account_customers if cus.email == stripe_email]
    # If there was no customer, need to create a new platform customer
    if not platform_customer:
      return
      #later when stripe is made compulsory, if user has not created an account yet, force it on him
      stripe_customer = stripe.Customer.create(
          email=stripe_email,
          source=stripe_token,
      )
      # Check if we had the customer in he db
      if not db.session.query(Business).filter('email' == stripe_email).count():
          #Create the db user
          new_customer = Business(
              stripe_id=stripe_customer.stripe_id,
              email=stripe_customer.email,
              account_balance=stripe_customer.account_balance,
              creation_time=stripe_customer.created,
              currency=stripe_customer.currency,
              delinquent=stripe_customer.delinquent,
              description=stripe_customer.description,
          )
          db.session.add(new_customer)
          db.session.commit()

      # Need to recreate the token to be able to crete the customer on the connected account too
      cus_token = stripe.Token.create(
          customer=stripe_customer.id,
          stripe_account=connected_user_id
      )
      # Create the customer in the connected account
      connected_account_customer = stripe.Customer.create(
          email=stripe_customer.email,
          source=cus_token.id,
          stripe_account=connected_user_id,
      )
      # Make the charge to the customer on the connected account
      stripe.Charge.create(
          amount=amount,
          currency='eur',
          customer=connected_account_customer.id,
          stripe_account=connected_user_id,
          application_fee=1,
      )
    # Just make the charge
    else:
        # Amount is always in cents
        stripe.Charge.create(
            amount=amount,
            currency='usd',
            source=stripe_token,
            stripe_account=connected_user_id,
            application_fee=0.1,
        )
  '''
