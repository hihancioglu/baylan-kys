import os
from datetime import datetime, timedelta

import jwt
import ldap3
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
from functools import wraps

from models import get_session, User, Role

auth_bp = Blueprint('auth', __name__)


def _ensure_user(username: str, email: str | None = None):
    session_db = get_session()
    try:
        user = session_db.query(User).filter_by(username=username).first()
        if not user:
            user = User(username=username, email=email)
            session_db.add(user)
            session_db.commit()
        roles = [role.name for role in user.roles]
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


def ldap_auth(username: str, password: str) -> bool:
    uri = current_app.config.get("LDAP_URL")
    domain = current_app.config.get("LDAP_DOMAIN")
    if not uri or not password:
        return False
    user_dn = f"{domain}\\{username}" if domain else username
    try:
        server = ldap3.Server(uri, get_info=ldap3.NONE)
        conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
        conn.unbind()
        return True
    except Exception:
        return False


def init_app(app):
    """Initialize authentication config."""
    app.config['LDAP_URL'] = os.environ.get('LDAP_URL', 'ldap://localhost')
    app.config['LDAP_DOMAIN'] = os.environ.get('LDAP_DOMAIN', '')
    app.config['JWT_SECRET'] = os.environ.get(
        'PORTAL_JWT_SECRET', app.secret_key
    )
    app.config['JWT_ACCESS_MINUTES'] = int(os.environ.get('JWT_ACCESS_MINUTES', 15))
    app.config['JWT_REFRESH_DAYS'] = int(os.environ.get('JWT_REFRESH_DAYS', 7))


@auth_bp.route('/login')
def login():
    """Render LDAP login form."""
    return render_template('login.html', breadcrumbs=[{"title": "Login"}])


@auth_bp.route('/logout')
def logout():
    """Clear the user session and redirect to login."""
    session.clear()
    resp = redirect(url_for('auth.login'))
    resp.delete_cookie('access_token')
    resp.delete_cookie('refresh_token')
    return resp


@auth_bp.post('/api/auth/login')
def api_login():
    """Authenticate user via LDAP."""
    data = request.get_json(silent=True) or request.form
    username = data.get('username')
    password = data.get('password')
    wants_json = request.is_json or request.accept_mimetypes.best == 'application/json'
    if not username or not password:
        if wants_json:
            return jsonify(error='Missing credentials'), 400
        return render_template('login.html', error='Missing credentials', breadcrumbs=[{"title": "Login"}]), 400

    if not ldap_auth(username, password):
        if wants_json:
            return jsonify(error='Invalid credentials'), 401
        return render_template('login.html', error='Invalid credentials', breadcrumbs=[{"title": "Login"}]), 401

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
    session['user'] = {'id': user_id, 'username': username, 'name': username}
    session['roles'] = roles
    if wants_json:
        resp = jsonify(status='ok')
    else:
        resp = redirect(url_for('dashboard'))
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
