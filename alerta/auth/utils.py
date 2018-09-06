
from datetime import datetime, timedelta
from flask import request, current_app
from six import text_type
from uuid import uuid4

from alerta.exceptions import ApiError, NoCustomerMatch
from alerta.models.customer import Customer
from alerta.models.permission import Permission
from alerta.models.token import Jwt
from alerta.utils.api import absolute_url
from alerta.app import mailer


try:
    import bcrypt  # type: ignore

    def generate_password_hash(password):
        if isinstance(password, text_type):
            password = password.encode('utf-8')
        return bcrypt.hashpw(password, bcrypt.gensalt(prefix=b'2a')).decode('utf-8')

    def check_password_hash(pwhash, password):
        return bcrypt.checkpw(password.encode('utf-8'), pwhash.encode('utf-8'))

except ImportError:  # Google App Engine
    from werkzeug.security import generate_password_hash, check_password_hash


def not_authorized(allowed_setting, groups):
    return (current_app.config['AUTH_REQUIRED']
            and not ('*' in current_app.config[allowed_setting]
                     or set(current_app.config[allowed_setting]).intersection(set(groups))))


def get_customers(login, groups):
    if current_app.config['CUSTOMER_VIEWS']:
        try:
            return Customer.lookup(login, groups)
        except NoCustomerMatch as e:
            raise ApiError(str(e), 403)
    else:
        return


def create_token(user_id, name, login, provider, customers, orgs=None, groups=None, roles=None, email=None, email_verified=None):
    now = datetime.utcnow()
    scopes = Permission.lookup(login, groups=(roles or []) + (groups or []) + (orgs or []))
    return Jwt(
        iss=request.url_root,
        sub=user_id,
        aud=current_app.config.get('OAUTH2_CLIENT_ID', None) or request.url_root,
        exp=(now + timedelta(days=current_app.config['TOKEN_EXPIRE_DAYS'])),
        nbf=now,
        iat=now,
        jti=str(uuid4()),
        name=name,
        preferred_username=login,
        orgs=orgs,
        roles=roles,
        groups=groups,
        provider=provider,
        scopes=scopes,
        email=email,
        email_verified=email_verified,
        customers=customers
    )


def send_confirmation(user):

    hash = str(uuid4())
    user.set_email_hash(hash)

    text = 'Hello {name}!\n\n' \
           'Please verify your email address is {email} by clicking on the link below:\n\n' \
           '{url}\n\n' \
           'You\'re receiving this email because you recently created a new Alerta account.' \
           ' If this wasn\'t you, please ignore this email.'.format(
               name=user.name, email=user.email, url='http://localhost:8000/#/confirm/' + hash
           )
    mailer.send_email(user.email, body=text)


def send_password_reset(user):

    hash = str(uuid4())
    user.set_email_hash(hash)

    text = 'You forgot your password. Reset it by clicking on the link below:\n\n' \
            '{url}\n\n' \
           'You\'re receiving this email because you asked for a password reset of an Alerta account.' \
           ' If this wasn\'t you, please ignore this email.'.format(
        name=user.name, email=user.email, url='http://localhost:8000/#/reset/' + hash
    )
    mailer.send_email(user.email, body=text)
