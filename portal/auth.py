import os
from datetime import datetime, timedelta

import jwt
from ldap3 import Connection, Server, ALL, NTLM, SIMPLE
from ldap3.core.exceptions import LDAPException
from urllib.parse import urlparse
from flask import (
    Blueprint,
    redirect,
    url_for,
    session,
    request,
    jsonify,
    current_app,
    render_template,
    abort,
)
from authlib.integrations.flask_client import OAuth
from functools import wraps

from models import get_session, User, Role

oauth = OAuth()
auth_bp = Blueprint('auth', __name__)


def _ensure_user(username: str, email: str | None = None):
    session_db = get_session()
    try:
        user = session_db.query(User).filter_by(username=username).first()
        if not user:
            user = User(username=username, email=email)
            session_db.add(user)
            session_db.commit()
        roles = [ur.role.name for ur in user.roles]
        return user.id, roles
    finally:
        session_db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('auth.login'))
        return view(*args, **kwargs)

    return wrapped


def roles_required(*required_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get('user'):
                return redirect(url_for('auth.login'))
            user_roles = session.get('roles', [])
            role_names = [r.value if hasattr(r, 'value') else r for r in required_roles]
            if role_names and not any(r in user_roles for r in role_names):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def _ldap_authenticate(username: str, password: str) -> bool:
    """Authenticate a user against LDAP using a service account."""
    timeout = current_app.config.get('LDAP_CONNECT_TIMEOUT', 5)
    # Parse the LDAP URL so we honour scheme and custom ports.
    url = urlparse(current_app.config['LDAP_URL'])
    use_ssl = url.scheme == 'ldaps'
    port = url.port or (636 if use_ssl else 389)
    host = url.hostname or current_app.config['LDAP_URL']
    server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=timeout)

    domain = current_app.config.get('LDAP_DOMAIN')
    bind_user = current_app.config.get('LDAP_USER')
    bind_password = current_app.config.get('LDAP_PASSWORD')
    base_dn = current_app.config.get('LDAP_BASE_DN')
    search_filter = current_app.config.get('LDAP_SEARCH_FILTER', '(objectClass=user)')

    auth_method = NTLM if domain else SIMPLE

    try:
        with Connection(
            server,
            user=f"{domain}\\{bind_user}" if domain else bind_user,
            password=bind_password,
            authentication=auth_method,
            auto_bind=True,
            receive_timeout=timeout,
        ) as conn:
            full_filter = f"(&{search_filter}(sAMAccountName={username}))"
            conn.search(base_dn, full_filter, attributes=['distinguishedName'])
            if not conn.entries:
                return False

        with Connection(
            server,
            user=f"{domain}\\{username}" if domain else username,
            password=password,
            authentication=auth_method,
            auto_bind=True,
            receive_timeout=timeout,
        ) as user_conn:
            return user_conn.bound
    except LDAPException as exc:
        current_app.logger.warning("LDAP authentication failed: %s", exc)
        return False


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
    app.config['LDAP_DOMAIN'] = os.environ.get('LDAP_DOMAIN', '')
    app.config['LDAP_USER'] = os.environ.get('LDAP_USER', '')
    app.config['LDAP_PASSWORD'] = os.environ.get('LDAP_PASSWORD', '')
    app.config['LDAP_BASE_DN'] = os.environ.get(
        'LDAP_BASE_DN', 'dc=example,dc=com'
    )
    app.config['LDAP_SEARCH_FILTER'] = os.environ.get(
        'LDAP_SEARCH_FILTER', '(objectClass=user)'
    )
    app.config['LDAP_CONNECT_TIMEOUT'] = int(os.environ.get('LDAP_CONNECT_TIMEOUT', 5))
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
    wants_json = request.is_json or request.accept_mimetypes.best == 'application/json'
    if not username or not password:
        if wants_json:
            return jsonify(error='Missing credentials'), 400
        return render_template('login.html', error='Missing credentials'), 400

    if not _ldap_authenticate(username, password):
        if wants_json:
            return jsonify(error='Invalid credentials'), 401
        return render_template('login.html', error='Invalid credentials'), 401

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
    user_id, roles = _ensure_user(username)
    session['user'] = {'id': user_id, 'username': username}
    session['roles'] = roles
    if wants_json:
        resp = jsonify(status='ok')
    else:
        resp = redirect(url_for('index'))
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
    username = user_info.get('preferred_username') or user_info.get('email') or user_info.get('sub')
    user_id, roles = _ensure_user(username, user_info.get('email'))
    session['user'] = {'id': user_id, 'username': username, 'email': user_info.get('email')}
    session['roles'] = roles
    return redirect(url_for('index'))
