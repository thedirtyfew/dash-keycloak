import sys

import dash
import dash_core_components as dcc
import dash_html_components as html

from dash.dependencies import Input, Output
from flask import Flask, session
from flask_keycloak import FlaskKeycloak

# Read config path from cmd if provided.
config_path = None if len(sys.argv) < 2 else sys.argv[1]
# Setup server.
server = Flask(__name__)
FlaskKeycloak.from_kc_oidc_json(server, "http://localhost:5000/", config_path=config_path)
# Setup dash app.
app = dash.Dash(__name__, server=server)
app.layout = html.Div(id="main", children=[html.Div(id="greeting"), dcc.LogoutButton(logout_url='/logout')])


@app.callback(
    Output('greeting', 'children'),
    [Input('main', 'children')])
def update_greeting(input_value):
    user = session["user"]
    return "Hello {}".format(user['preferred_username'])


if __name__ == '__main__':
    app.run_server(port=5000)

