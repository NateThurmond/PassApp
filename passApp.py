from flask import Flask, request, render_template, make_response, send_file, abort
from sql import PassAppDB
import os
from io import BytesIO

app = Flask(__name__)

db = PassAppDB()

# Sample DB methods (for later use and implementation)
# testUserName = 'testusd2gdffr4'
# testUserEmail = testUserName + '@gmail.com'
# print('CHECK USER UNIQUENESS:', db.check_user_uniqueness(testUserName, testUserEmail))
# db.add_user(
#     testUserName,
#     testUserEmail,
#     'df2f82mffgdfgdf2',
#     'oldSalty1234'
# )
# print('IS LOGIN VALID:', db.validate_login(testUserName, 'df2f82mffgdfgdf2', '1.2.3.4'))

'''
Phased rollout plan for implementation


1. Limit brute force attempts on KeePass file
- Limit attempts per IP/session
- Add delays or lockout after 5 failed tries

2. Generate a session UUID on successful unlock
- Passwords are only sent hashed to server for identification
- random uuid4 for authenticated sessions:
- Acts as your session identifier
- Should be tied to client via secure cookie

3. Store session metadata in a DB, store the following:
- session UUID
- Salted + hashed user identification password (e.g. bcrypt)
- Network file path
- Expiration timestamp
- Number of failed attempts
- IP/user-agent

4. Server returns kdbx file to client
- Client uses PBKDF2 to decrypt kdbx file sent from server
- Allows for zero-knowledge server architecture

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
        KEEPASS_FILE_PATH=KEEPASS_FILE_PATH
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

if __name__ == '__main__':
    app.run(debug=True)