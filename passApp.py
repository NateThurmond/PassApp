from flask import Flask, request, render_template, make_response, send_file, abort, jsonify
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from sql import PassAppDB
import os
from io import BytesIO
from dotenv import load_dotenv

# Load the variables from the .env file
load_dotenv()

config_version = '0.0.1'

# SRP constants
N_HEX = (
  "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
  "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
  "E8083969EDB767B0CF6096C3D6A9F0BFF5CB6F406B7EDEE386BFB5A899FA5AE9"
  "F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A691"
  "63FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670"
  "C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
)
G = 2  # generator
HASH = "SHA-256"

app = Flask(__name__)
app.secret_key = os.getenv('CSRF_SECRET_KEY')
CSRFProtect(app)

# 1 hop: ALB -> app. If Cloudflare+ALB, use x_for=2.
# Make sure to set this right based on your deployment env
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://", # Swap out w/ Redis for AWS or prod site
    # storage_uri="redis://localhost:6379/0", # Example
)
limiter.init_app(app)

db = PassAppDB()

@app.route('/', methods=['GET', 'POST'])
def index():
    token = generate_csrf()
    KEEPASS_FILE_PATH = ''
    KEEPASS_FILE_PASS = ''
    message = 'File not found'
    entries = []

    if request.method == 'POST':
        KEEPASS_FILE_PATH = request.form.get('keepass_path')
        KEEPASS_FILE_PASS = request.form.get('keepass_pass')
        user_name = request.form.get('user_name')
        if user_name is not None:
            print('Check User Uniqueness: ', user_name, db.check_user_uniqueness(user_name, user_name))
    else:
        existingCookie = request.cookies.get('keepass_path')
        if existingCookie:
            KEEPASS_FILE_PATH = existingCookie

    if os.path.exists(KEEPASS_FILE_PATH) and KEEPASS_FILE_PASS:
        message = 'Pass DB File Found'

    renderVars = dict(
        message=message,
        entries=entries,
        KEEPASS_FILE_PATH=KEEPASS_FILE_PATH,
        token=token
    )

    response = make_response(render_template('index.html', **renderVars))
    if request.method == 'POST':
        response.set_cookie('keepass_path', KEEPASS_FILE_PATH, max_age=60*60*24*365)
    return response

@app.route('/download-vault', methods=['POST'])
def download_vault():
    KEEPASS_FILE_PATH = request.form.get('keepass_path')

    if not KEEPASS_FILE_PATH or not os.path.exists(KEEPASS_FILE_PATH):
        return abort(404)

    # Read the raw .kdbx for delivery back to client
    with open(KEEPASS_FILE_PATH, 'rb') as f:
        kdbx_data = f.read()

    return send_file(
        BytesIO(kdbx_data),
        mimetype='application/octet-stream',
        as_attachment=False,
        download_name='vault.kdbx'
    )

@app.route('/signUpCheckUser', methods=['POST'])
@limiter.limit("5/minute;30/hour")
def signUpCheckUser():

    user_name = (request.form.get('up_user_name') or "").strip().lower()
    user_email = (request.form.get('up_user_email') or "").strip().lower()

    if not user_name or not user_email:
        message = "Missing required fields"
    else:
        if not db.check_user_name_uniqueness(user_name):
            message = "Username not available"
        else:
            message = "Username/email available"

    return jsonify({"msg": message, "config_version": config_version}), 200

@app.route('/signUp', methods=['POST'])
@limiter.limit("5/minute;30/hour")
def signUp():

    user_name = (request.form.get('up_user_name') or "").strip().lower()
    user_email = (request.form.get('up_user_email') or "").strip().lower()
    salt = (request.form.get('salt') or "").strip().lower()
    verifier = (request.form.get('verifier') or "").strip().lower()

    # Not currently used but they are passed
    # group = (request.form.get('group') or "").strip().lower()
    # hash = (request.form.get('hash') or "").strip().lower()
    # g = (request.form.get('g') or "").strip().lower()

    # TO-DO: Lots more checks here
    '''
    - Need to verify user name and email are required length and valid format (email)
    - Need to make sure salt and verifier are valid hex strings
    - make sure verifier is hex and in range 1..N-1 for your SRP group
    - potentially Limit request size (only if doesn't affect kdbx vault downloads)
    '''

    if not user_name or not user_email or not salt or not verifier:
        message = "Missing required fields"
    else:
        if not db.check_user_uniqueness(user_name, user_email):
            message = "Username not available"
        elif not db.add_user(user_name, user_email, salt, verifier):
            message = "Failed to add user"
        else:
            message = "User successfully added"

    return jsonify({"msg": message, "config_version": config_version}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5001)