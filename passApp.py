from flask import Flask, request, render_template, make_response, send_file, abort, jsonify
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from email.utils import parseaddr
from sql import PassAppDB
import os, hashlib, re, hmac
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

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
N = int(N_HEX, 16)  # from SRP constant above
LEN_N = (N.bit_length() + 7) // 8

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

# TO-DO: Migrate these methods to class or imported functions file
# TO-DO: May end up differentiating between std helper fns and SRP specific ones

# SRP START METHODS - START

def H_bytes(*args):
    """Hash and return integer."""
    h = hashlib.sha256()
    for a in args:
        h.update(a)
    return int.from_bytes(h.digest(), 'big')

def int_to_bytes(i):
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, 'big')

# Generate server private ephemeral b (random)
def generate_b(num_bytes=32):
    return int.from_bytes(os.urandom(num_bytes), 'big')

# Compute B = (k*v + g^b mod N) mod N - Hex returned to client as part of SRP
def compute_B(v_hex, b):
    v = int(v_hex, 16)
    k = H_bytes(int_to_bytes(N), int_to_bytes(G))
    return (k * v + pow(G, b, N)) % N

# SRP START METHODS - END


# SRP VERIFY METHODS - START

def pad(i):
    b = int_to_bytes(i)
    return b if len(b) >= LEN_N else (b'\x00' * (LEN_N - len(b))) + b

def H_bytes_concat(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()

def H_int(*parts):
    return int.from_bytes(H_bytes_concat(*parts), 'big')

def verify_m1(username: str, salt_hex: str, A_hex: str, b_hex: str, v_hex: str, m1_hex: str):
    # inputs as hex (except username); returns (ok, M2_hex, K_hex)
    A = int(A_hex, 16)
    b = int(b_hex, 16)
    v = int(v_hex, 16)
    s = bytes.fromhex(salt_hex)

    # k = H(N || g)
    k = H_int(int_to_bytes(N), int_to_bytes(G))

    # B = (k*v + g^b) mod N
    B = (k * v + pow(G, b, N)) % N
    if A % N == 0 or B % N == 0:
        return (False, None, None)

    # u = H( PAD(A) || PAD(B) )
    u = H_int(int_to_bytes(A), int_to_bytes(B))

    # S_server = (A * v^u)^b mod N
    Avu = (A * pow(v, u, N)) % N
    S = pow(Avu, b, N)

    # K = H(S)
    K_bytes = H_bytes_concat(int_to_bytes(S))
    K_hex = K_bytes.hex()

    # M1 = H( H(N) XOR H(g), H(I), s, A, B, K )
    HN = H_bytes_concat(int_to_bytes(N))
    Hg = H_bytes_concat(int_to_bytes(G))
    Hxor = bytes(a ^ b for a, b in zip(HN, Hg))
    HI = H_bytes_concat(username.encode('utf-8'))
    M1_calc = H_bytes_concat(Hxor, HI, s, int_to_bytes(A), int_to_bytes(B), K_bytes)

    ok = hmac.compare_digest(M1_calc.hex(), m1_hex.lower())
    if not ok:
        return (False, None, None)

    # M2 = H( A, M1, K )  (common SRP-6a server proof)
    M2 = H_bytes_concat(int_to_bytes(A), M1_calc, K_bytes).hex()
    return (True, M2, K_hex)

# SRP VERIFY METHODS - END


# Helper fn for some of the later post methods
def is_valid_email(addr):
    name, email_addr = parseaddr(addr)
    return '@' in email_addr and '.' in email_addr.split('@')[-1]

# Same as above, validate some post data
def is_valid_hex(s, min_len = None):
    if not HEX_RE.fullmatch(s):
        return False
    return min_len is None or len(s) >= min_len

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

    if request.content_length and request.content_length > 500 * 1024:
        abort(413)

    user_name = (request.form.get('up_user_name') or "").strip().lower()
    user_email = (request.form.get('up_user_email') or "").strip().lower()
    salt = (request.form.get('salt') or "").strip().lower()
    verifier = (request.form.get('verifier') or "").strip().lower()

    # SRP range check for verifier - for validation check later
    v_int = int(verifier, 16)

    # Not currently used but they are passed
    # group = (request.form.get('group') or "").strip().lower()
    # hash = (request.form.get('hash') or "").strip().lower()
    # g = (request.form.get('g') or "").strip().lower()

    if not user_name or not user_email or not salt or not verifier:
        message = "Missing required fields"
    elif len(user_name) < 3 or len(user_name) > 32:
        message = "Username must be between 3 and 32 characters"
    elif len(user_email) < 5 or len(user_email) > 64:
        message = "Email must be between 5 and 64 characters"
    elif not is_valid_email(user_email):
        message = "Invalid email format"
    elif not is_valid_hex(salt, 32):
        message = "Salt must be a valid 32-character hex string"
    elif not is_valid_hex(verifier, 64):
        message = "Verifier must be a valid 64-character hex string"
    elif not (1 <= v_int < N):
        message = "Invalid verifier value"
    else:
        if not db.check_user_uniqueness(user_name, user_email):
            message = "Username not available"
        elif not db.add_user(user_name, user_email, salt, verifier):
            message = "Failed to add user"
        else:
            message = "User successfully added"

    return jsonify({"msg": message, "config_version": config_version}), 200

@app.route('/login/srp/start', methods=['POST'])
@limiter.limit("5/minute;30/hour")
def loginSrpStart():

    if request.content_length and request.content_length > 500 * 1024:
        abort(413)

    user_name = (request.form.get('login_user_name') or "").strip().lower()
    clientEphemeralA = (request.form.get('clientEphemeralA') or "").strip().lower()
    foundUserSaltAndVerifier = db.get_user_salt(user_name)

    foundUserSalt = ''
    foundUserSalt = ''
    B_hex = ''
    if foundUserSaltAndVerifier and foundUserSaltAndVerifier.get('salt'):
        foundUserSalt = foundUserSaltAndVerifier['salt']
    if foundUserSaltAndVerifier and foundUserSaltAndVerifier.get('verifier'):
        foundUserVerifier = foundUserSaltAndVerifier['verifier']

    if not user_name or not clientEphemeralA:
        message = "Missing required fields"
    elif not is_valid_hex(clientEphemeralA, 365):
        message = "Client Ephemeral A must be a valid 365-character hex string"
    elif not foundUserSaltAndVerifier:
        message = "User not found"
    else:
        serverPrivate_b = generate_b() # store in short-lived session
        clientEphemeral_B = compute_B(foundUserVerifier, serverPrivate_b) # return to client for M1 calculation
        B_hex = format(clientEphemeral_B, 'x') # As hex
        accessionEntropyId = db.store_short_lived_srp(user_name, clientEphemeralA, format(serverPrivate_b, 'x'), foundUserVerifier)

        if not accessionEntropyId:
            message = "Failed to register short-lived SRP"
        else:
            message = "All Okay"

    return jsonify({"msg": message, "B": B_hex, "Salt": foundUserSalt,
        "config_version": config_version, "accessionId": accessionEntropyId}), 200

@app.route('/login/srp/verify', methods=['POST'])
@limiter.limit("5/minute;30/hour")
def loginSrpVerify():

    if request.content_length and request.content_length > 500 * 1024:
        abort(413)

    client_proof_m1 = (request.form.get('client_proof_m1') or "").strip().lower()
    user_name = (request.form.get('login_user_name') or "").strip().lower()
    accessionId = (request.form.get('accessionId') or "").strip()

    foundUserSalt = ''
    empheralA = ''
    empheralB = ''
    verifier = ''

    # DB call to get srp short lived session data and salt based on username and accessionId
    foundUserSaltAndVerifier = db.get_user_salt(user_name)
    shortLivedSrp = db.get_short_lived_srp(user_name, accessionId)

    if foundUserSaltAndVerifier and foundUserSaltAndVerifier.get('salt'):
        foundUserSalt = foundUserSaltAndVerifier['salt']

    if shortLivedSrp and shortLivedSrp.get('verifier'):
        empheralA = shortLivedSrp['empheralA']
        empheralB = shortLivedSrp['empheralB']
        verifier = shortLivedSrp['verifier']

    # Delete short lived srp session data regardless of results above
    db.delete_short_lived_srp(user_name)

    # The magic (certainly magic to me - I don't pretend to understand the math)
    proof_match = verify_m1(
        username=user_name,
        salt_hex=foundUserSalt,
        A_hex=empheralA, #clientEphemeralA
        b_hex=empheralB, #serverEphemeralB
        v_hex=verifier, #verifier
        m1_hex=client_proof_m1
    ) if foundUserSaltAndVerifier and shortLivedSrp else False

    if not user_name or not client_proof_m1 or not accessionId:
        message = "Missing required fields"
    elif not is_valid_hex(client_proof_m1, 64):
        message = "Client Proof not valid"
    elif not proof_match or not proof_match[0]:
        message = "Invalid login"
    else:
        # TO-DO: Set session login (cookie) (and store)
        message = "Login successful!"

    return jsonify({"msg": message, "config_version": config_version}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5001)