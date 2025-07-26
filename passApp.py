from flask import Flask, request, render_template, make_response
from pykeepass import PyKeePass
import os

app = Flask(__name__)

'''
Phased rollout plan for implementation

1. Limit brute force attempts on KeePass file
- Limit attempts per IP/session
- Add delays or lockout after 5 failed tries

2. Generate a session UUID on successful unlock
- random uuid4 for authenticated sessions:
- Acts as your session identifier
- Should be tied to client via secure cookie

3. Store session metadata in a DB, store the following:
- session UUID
- Salted + hashed KeePass password (e.g. bcrypt)
- Network file path
- Expiration timestamp
- Number of failed attempts
- IP/user-agent

Extra Options (later):
- Add 2FA or password re-entry for certain routes
- Encrypt session DB contents at rest
- Rate-limit unlock attempts per session/IP
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    KEEPASS_FILE_PATH = ''
    KEEPASS_FILE_PASS = ''
    message = 'File not found'
    entries = []

    if request.method == 'POST':
        KEEPASS_FILE_PATH = request.form.get('keepass_path')
        KEEPASS_FILE_PASS = request.form.get('keepass_pass')
    else:
        existingCookie = request.cookies.get('keepass_path')
        if existingCookie:
            KEEPASS_FILE_PATH = existingCookie

    if os.path.exists(KEEPASS_FILE_PATH) and KEEPASS_FILE_PASS:
        message = 'Pass DB File Found'
        kp = PyKeePass(KEEPASS_FILE_PATH, password=KEEPASS_FILE_PASS)
        entries = kp.entries

    renderVars = dict(
        message=message,
        entries=entries,
        KEEPASS_FILE_PATH=KEEPASS_FILE_PATH
    )

    response = make_response(render_template('index.html', **renderVars))
    if request.method == 'POST':
        response.set_cookie('keepass_path', KEEPASS_FILE_PATH, max_age=60*60*24*365)
    return response

if __name__ == '__main__':
    app.run(debug=True)