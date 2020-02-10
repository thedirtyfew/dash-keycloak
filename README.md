This purpose of this library is to provide seamless integration of Plotly Dash with keycloak via the python-keycloak package.

#### Prerequisites

Prior to using this library, a Keycloak server must be setup. Please refer to the official documentation,

    https://www.keycloak.org/

After setting up the server, create a client for the application. Set "Access Type" to "confidential", set the valid redirect URIs (mandatory), and click "Save". Go to "Installation", select "Keycloak OIDC JSON" as "Format Option" and download the file.

#### Installation

To run the code, a virtual environment should be setup,

    python3 -m venv venv
    
After activating the environment,

    source venv/bin/activate
    
The relevant packages can be installed as

    pip install -r requirements.txt

#### Running the example

After completing the above step, the example can be run with the command

    python3 -m flask_keycloak.examples.dash_example /path/to/keycloak.json 

#### Deployment

Bump the version number in setup.py and run

    python3 setup.py sdist
    pip3 install twine
    twine upload dist/*
