from flask import Blueprint, redirect, url_for, session
from authlib.integrations.flask_client import OAuth

oauth = OAuth()
auth_bp = Blueprint('auth', __name__)


def init_app(app):
    """Initialize OAuth client with application config."""
    oauth.init_app(app)
    oauth.register(
        name='oidc',
        client_id=app.config['OIDC_CLIENT_ID'],
        client_secret=app.config['OIDC_CLIENT_SECRET'],
        server_metadata_url=f"{app.config['OIDC_ISSUER']}/.well-known/openid-configuration",
        client_kwargs={'scope': 'openid profile email'},
    )


@auth_bp.route('/login')
def login():
    """Redirect user to the identity provider."""
    redirect_uri = url_for('auth.oidc_callback', _external=True)
    return oauth.oidc.authorize_redirect(redirect_uri)


@auth_bp.route('/oidc/callback')
def oidc_callback():
    """Handle IdP callback and persist user info in session."""
    token = oauth.oidc.authorize_access_token()
    user_info = token.get('userinfo') or oauth.oidc.parse_id_token(token)
    session['user'] = user_info
    return redirect(url_for('index'))
