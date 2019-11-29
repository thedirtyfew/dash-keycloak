import json
import urllib.parse

from flask import redirect, session
from keycloak import KeycloakOpenID
from werkzeug.wrappers import Request


class Objectify(object):
    def __init__(self, **kwargs):
        self.__dict__.update({key.lower(): kwargs[key] for key in kwargs})


class AuthMiddleWare:
    def __init__(self, app, config, session_interface, keycloak_openid, redirect_uri):
        self.app = app
        self.config = config
        self.session_interface = session_interface
        self.keycloak_openid = keycloak_openid
        self.redirect_uri = redirect_uri
        # Create object representation of config.
        self.config_object = Objectify(config=config, **config)
        # Setup uris.
        parse_result = urllib.parse.urlparse(redirect_uri)
        self.callback_path = "/keycloak/callback"
        self.callback_uri = parse_result._replace(path=self.callback_path).geturl()
        self.auth_uri = self.keycloak_openid.auth_url(self.callback_uri)

    def __call__(self, environ, start_response):
        response = None
        request = Request(environ)
        session = self.session_interface.open_session(self.config_object, request)

        # On callback, request access token.
        if request.path == self.callback_path:
            response = self.set_access_token(session, request)

        # If unauthorized, redirect to login page.
        if self.callback_path not in request.path and "token" not in session:
            response = redirect(self.auth_uri)

        # Save the session.
        if response:
            self.session_interface.save_session(self.config_object, session, response)
            return response(environ, start_response)

        # Request is authorized, just proceed.
        return self.app(environ, start_response)

    def set_access_token(self, session, request):
        # Get access token from Keycloak.
        token = self.keycloak_openid.token(grant_type=["authorization_code"],
                                           code=request.args.get("code", "unknown"),
                                           redirect_uri=self.callback_uri)
        user = self.keycloak_openid.userinfo(token['access_token'])
        # Bind token and user info to the session.
        session["token"] = token
        session["user"] = user
        # Redirect to the desired uri, i.e. the post login page.
        return redirect(self.redirect_uri)


class FlaskKeycloak:
    def __init__(self, app, keycloak_openid, redirect_uri, logout_path=None):
        logout_path = '/logout' if logout_path is None else logout_path
        # Bind secret key.
        if keycloak_openid._client_secret_key is not None:
            app.config['SECRET_KEY'] = keycloak_openid._client_secret_key
        # Add middleware.
        app.wsgi_app = AuthMiddleWare(app.wsgi_app, app.config, app.session_interface, keycloak_openid, redirect_uri)
        # Add logout mechanism.
        if logout_path:
            @app.route(logout_path, methods=['POST'])
            def route_logout():
                keycloak_openid.logout(session["token"]["refresh_token"])
                session.clear()
                return redirect(redirect_uri)

    @staticmethod
    def from_kc_oidc_json(app, redirect_uri, config_path=None, logout_path=None, keycloak_kwargs=None):
        # Read config, assumed to be in Keycloak OIDC JSON format.
        config_path = "keycloak.json" if config_path is None else config_path
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        # Setup the Keycloak connection.
        keycloak_config = dict(server_url=config_data["auth-server-url"],
                               realm_name=config_data["realm"],
                               client_id=config_data["resource"],
                               client_secret_key=config_data["credentials"]["secret"],
                               verify=config_data["ssl-required"] != "none")
        if keycloak_kwargs is not None:
            keycloak_config = {**keycloak_config, **keycloak_kwargs}
        keycloak_openid = KeycloakOpenID(**keycloak_config)
        return FlaskKeycloak(app, keycloak_openid, redirect_uri, logout_path=logout_path)
