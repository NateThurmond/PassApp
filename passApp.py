from flask import Flask, request, render_template, make_response
from pykeepass import PyKeePass
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    KEEPASS_FILE_PATH = ''
    message = 'File not found'
    entries = []

    if request.method == 'POST':
        KEEPASS_FILE_PATH = request.form.get('keepass_path')
    else:
        existingCookie = request.cookies.get('keepass_path')
        if existingCookie:
            KEEPASS_FILE_PATH = existingCookie

    if os.path.exists(KEEPASS_FILE_PATH):
        message = 'Pass DB File Found'
        kp = PyKeePass(KEEPASS_FILE_PATH, password='xxxxxx')
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