import os
from flask import current_app


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'doc', 'docx', 'xls', 'xlsx'}

def init_upload(app):
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def create_folder():
    upload_folder = os.path.join(os.getcwd(), 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    return upload_folder

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_user_folder(username):
    # Get upload folder path (you might want to store this in app config)
    upload_folder = os.path.join(os.getcwd(), 'uploads')
    user_folder = os.path.join(upload_folder, username)
    os.makedirs(user_folder, exist_ok=True)
    return user_folder