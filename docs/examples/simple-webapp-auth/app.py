
## Example from http://flask.pocoo.org/snippets/8/

from functools import wraps
from flask import Flask, request, Response

app = Flask(__name__)

def check_auth(username, password):
    return username == 'user' and password == 'pass'

def authenticate():
    return Response(
    'Could not verify login, please try again with correct credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

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









# def check_auth(username, password):
#     """This function is called to check if a username /
#     password combination is valid.
#     """
#     return username == 'admin' and password == 'secret'


    

# @app.route('/secret-page')
# @requires_auth
# def secret_page():
#     return render_template('secret_page.html')

