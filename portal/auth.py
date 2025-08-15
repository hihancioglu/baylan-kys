import os
from datetime import datetime, timedelta

import jwt
from ldap3 import Connection, Server, ALL
from flask import (
    Blueprint,
    redirect,
    url_for,
    session,
    request,
    jsonify,
    current_app,
    render_template,
)
from authlib.integrations.flask_client import OAuth

oauth = OAuth()
auth_bp = Blueprint('auth', __name__)


def init_app(app):
    """Initialize OAuth client and authentication config."""
    oauth.init_app(app)
    oauth.register(
        name='oidc',
        client_id=app.config['OIDC_CLIENT_ID'],
        client_secret=app.config['OIDC_CLIENT_SECRET'],
        server_metadata_url=f"{app.config['OIDC_ISSUER']}/.well-known/openid-configuration",
        client_kwargs={'scope': 'openid profile email'},
    )

    app.config['LDAP_ENABLED'] = os.environ.get('LDAP_ENABLED', '').lower() == 'true'
    app.config['LDAP_URL'] = os.environ.get('LDAP_URL', 'ldap://localhost')
    app.config['LDAP_USER_BASE'] = os.environ.get(
        'LDAP_USER_BASE', 'ou=users,dc=example,dc=com'
    )
    app.config['JWT_SECRET'] = os.environ.get(
        'PORTAL_JWT_SECRET', app.secret_key
    )
    app.config['JWT_ACCESS_MINUTES'] = int(os.environ.get('JWT_ACCESS_MINUTES', 15))
    app.config['JWT_REFRESH_DAYS'] = int(os.environ.get('JWT_REFRESH_DAYS', 7))


@auth_bp.route('/login')
def login():
    """Render LDAP login form or redirect to OIDC."""
    if current_app.config.get('LDAP_ENABLED'):
        return render_template('login.html')
    redirect_uri = url_for('auth.oidc_callback', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@auth_bp.post('/api/auth/login')
def api_login():
    """Authenticate user via LDAP or delegate to OIDC."""
    if not current_app.config.get('LDAP_ENABLED'):
        return redirect(url_for('auth.login'))

    data = request.get_json(silent=True) or request.form
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify(error='Missing credentials'), 400

    server = Server(current_app.config['LDAP_URL'], get_info=ALL)
    user_dn = f"uid={username},{current_app.config['LDAP_USER_BASE']}"
    try:
        Connection(server, user=user_dn, password=password, auto_bind=True)
    except Exception:
        return jsonify(error='Invalid credentials'), 401

    secret = current_app.config['JWT_SECRET']
    now = datetime.utcnow()
    access_payload = {
        'sub': username,
        'exp': now + timedelta(minutes=current_app.config['JWT_ACCESS_MINUTES'])
    }
    refresh_payload = {
        'sub': username,
        'exp': now + timedelta(days=current_app.config['JWT_REFRESH_DAYS'])
    }
    access_token = jwt.encode(access_payload, secret, algorithm='HS256')
    refresh_token = jwt.encode(refresh_payload, secret, algorithm='HS256')

    session['user'] = {'username': username}
    resp = jsonify(status='ok')
    resp.set_cookie('access_token', access_token, httponly=True, samesite='Strict')
    resp.set_cookie('refresh_token', refresh_token, httponly=True, samesite='Strict')
    return resp


@auth_bp.post('/api/auth/refresh')
def refresh():
    """Refresh access token using refresh token."""
    secret = current_app.config['JWT_SECRET']
    token = request.cookies.get('refresh_token')
    if not token:
        return jsonify(error='Missing refresh token'), 401
    try:
        data = jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify(error='Refresh token expired'), 401
    except jwt.InvalidTokenError:
        return jsonify(error='Invalid refresh token'), 401

    username = data.get('sub')
    now = datetime.utcnow()
    new_access = jwt.encode(
        {
            'sub': username,
            'exp': now + timedelta(minutes=current_app.config['JWT_ACCESS_MINUTES'])
        },
        secret,
        algorithm='HS256',
    )
    new_refresh = jwt.encode(
        {
            'sub': username,
            'exp': now + timedelta(days=current_app.config['JWT_REFRESH_DAYS'])
        },
        secret,
        algorithm='HS256',
    )
    resp = jsonify(status='refreshed')
    resp.set_cookie('access_token', new_access, httponly=True, samesite='Strict')
    resp.set_cookie('refresh_token', new_refresh, httponly=True, samesite='Strict')
    return resp


@auth_bp.route('/oidc/callback')
def oidc_callback():
    """Handle IdP callback and persist user info in session."""
    token = oauth.oidc.authorize_access_token()
    user_info = token.get('userinfo') or oauth.oidc.parse_id_token(token)
    session['user'] = user_info
    return redirect(url_for('index'))
