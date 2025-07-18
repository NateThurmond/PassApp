from flask import Flask, render_template
import os

app = Flask(__name__)

# Path to your KeePass database on a mounted network share
KEEPASS_FILE_PATH = r'/Volumes/Backups.backupdb/passClientsDb.kdbx'

@app.route('/')
def index():
    db_exists = 'File not found'
    if os.path.exists(KEEPASS_FILE_PATH):
        db_exists = 'Pass DB File Found'
    return render_template('index.html', message=db_exists)

if __name__ == '__main__':
    app.run(debug=True)