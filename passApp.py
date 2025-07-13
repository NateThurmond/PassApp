from flask import Flask
import os

app = Flask(__name__)

# Path to your KeePass database on a mounted network share
KEEPASS_FILE_PATH = r'/Volumes/networkShare/MyVault.kdbx'

@app.route('/')
def index():
    if os.path.exists(KEEPASS_FILE_PATH):
        return 'It exists'
    else:
        return 'File not found', 404

if __name__ == '__main__':
    app.run(debug=True)