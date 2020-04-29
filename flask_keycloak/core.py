import json
import logging
import urllib.parse
from flask import redirect, session, request
from keycloak import KeycloakOpenID, KeycloakGetError
from keycloak.exceptions import KeycloakConnectionError
from werkzeug.wrappers import Request


class Objectify(object):
    def __init__(self, **kwargs):
        self.__dict__.update({key.lower(): kwargs[key] for key in kwargs})


class AuthHandler:
    def __init__(self, app, config, session_interface, keycloak_openid):
        self.app = app
        self.config = config
        self.session_interface = session_interface
        self.keycloak_openid = keycloak_openid
        # Create object representation of config.
        self.config_object = Objectify(config=config, **config)

    def is_logged_in(self, request):
        return "token" in self.session_interface.open_session(self.config_object, request)

    def auth_url(self, callback_uri):
        return self.keycloak_openid.auth_url(callback_uri)

    def login(self, request, response, **kwargs):
        session = self.session_interface.open_session(self.config_object, request)
        # Get access token from Keycloak.
        token = self.keycloak_openid.token(**kwargs)
        # Get extra info.
        user = self.keycloak_openid.userinfo(token['access_token'])
        introspect = self.keycloak_openid.introspect(token['access_token'])
        # Bind token, userinfo, and token introspection to the session.
        session["token"] = token
        session["userinfo"] = user
        session["introspect"] = introspect
        # Save the session.
        self.session_interface.save_session(self.config_object, session, response)
        return response

    def logout(self, response=None):
        self.keycloak_openid.logout(session["token"]["refresh_token"])
        session.clear()
        return response


class AuthMiddleWare:
    def __init__(self, app, auth_handler, redirect_uri, uri_whitelist=None):
        self.app = app
        self.auth_handler = auth_handler
        self.redirect_uri = redirect_uri
        self.uri_whitelist = uri_whitelist
        # Setup uris.
        parse_result = urllib.parse.urlparse(redirect_uri)
        self.callback_path = "/keycloak/callback"
        self.callback_uri = parse_result._replace(path=self.callback_path).geturl()
        self.auth_uri = self.auth_handler.auth_url(self.callback_uri)

    def __call__(self, environ, start_response):
        response = None
        request = Request(environ)
        # If the uri has been whitelisted, just proceed.
        if self.uri_whitelist is not None and request.path in self.uri_whitelist:
            return self.app(environ, start_response)
        # On callback, request access token.
        if request.path == self.callback_path:
            kwargs = dict(grant_type=["authorization_code"],
                          code=request.args.get("code", "unknown"),
                          redirect_uri=self.callback_uri)
            response = self.auth_handler.login(request, redirect(self.redirect_uri), **kwargs)
        # If unauthorized, redirect to login page.
        if self.callback_path not in request.path and not self.auth_handler.is_logged_in(request):
            response = redirect(self.auth_uri)
        # Save the session.
        if response:
            return response(environ, start_response)
        # Request is authorized, just proceed.
        return self.app(environ, start_response)


class FlaskKeycloak:
    def __init__(self, app, keycloak_openid, redirect_uri, uri_whitelist=None, logout_path=None, heartbeat_path=None,
                 login_path=None):
        logout_path = '/logout' if logout_path is None else logout_path
        uri_whitelist = [] if uri_whitelist is None else uri_whitelist
        if heartbeat_path is not None:
            uri_whitelist = uri_whitelist + [heartbeat_path]
        if login_path is not None:
            uri_whitelist = uri_whitelist + [login_path]
        # Bind secret key.
        if keycloak_openid._client_secret_key is not None:
            app.config['SECRET_KEY'] = keycloak_openid._client_secret_key
        # Add middleware.
        auth_handler = AuthHandler(app.wsgi_app, app.config, app.session_interface, keycloak_openid)
        app.wsgi_app = AuthMiddleWare(app.wsgi_app, auth_handler, redirect_uri, uri_whitelist)
        # Add logout mechanism.
        if logout_path:
            @app.route(logout_path, methods=['POST'])
            def route_logout():
                return auth_handler.logout(redirect(redirect_uri))
        if login_path:
            @app.route(login_path, methods=['POST'])
            def route_login():
                return auth_handler.login(request, redirect(redirect_uri), **request.json)
        if heartbeat_path:
            @app.route(heartbeat_path, methods=['GET'])
            def route_heartbeat_path():
                return "Chuck Norris can kill two stones with one bird."

    @staticmethod
    def from_kc_oidc_json(app, redirect_uri, config_path=None, logout_path=None, heartbeat_path=None,
                          keycloak_kwargs=None, authorization_settings=None, uri_whitelist=None, login_path=None):
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
        if authorization_settings is not None:
            keycloak_openid.load_authorization_config(authorization_settings)
        return FlaskKeycloak(app, keycloak_openid, redirect_uri, logout_path=logout_path,
                             heartbeat_path=heartbeat_path, uri_whitelist=uri_whitelist, login_path=login_path)

    @staticmethod
    def try_from_kc_oidc_json(app, redirect_uri, **kwargs):
        success = True
        try:
            FlaskKeycloak.from_kc_oidc_json(app, redirect_uri, **kwargs)
        except FileNotFoundError:
            app.logger.exception("No keycloak configuration found, proceeding without authentication.")
            success = False
        except IsADirectoryError:
            app.logger.exception("Keycloak configuration was directory, proceeding without authentication.")
            success = False
        except KeycloakConnectionError:
            app.logger.exception("Unable to connect to keycloak, proceeding without authentication.")
            success = False
        except KeycloakGetError:
            app.logger.exception("Encountered keycloak get error, proceeding without authentication.")
            success = False
        return success
