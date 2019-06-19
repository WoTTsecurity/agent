
# Example from http://flask.pocoo.org/snippets/8/

from functools import wraps
from flask import Flask, request, Response, json

app = Flask(__name__)


def check_auth(username, password):

    # Loading credentials from json file
    with open('/opt/wott/credentials/my_simple_web_app.json', 'r') as creds:
        creds_info = json.load(creds)

    creds_values = creds_info['web_app_credentials'].split(":")
    new_username = creds_values[0]
    new_password = creds_values[1]

    return username == new_username and password == new_password


def authenticate():
    return Response(
        'Could not verify login, please try again with correct credentials',
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/')
@requires_auth
def hello_world():
    return 'Login successful. Hello from WoTT!'

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)
