import os
import jwt
import uuid
import logging
import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from flask_expects_json import expects_json
from flask import Flask, request, jsonify, make_response, send_file
from werkzeug.security import generate_password_hash, check_password_hash

from db import db
from models.user import User
from models.file import File
from config.schema import register_schema
from config.config import DB_URI, SECRET_KEY, MAX_SIZE, ALLOWED_EXTENSIONS


app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
# we don't want Flask's modification tracker
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['MAX_CONTENT_LENGTH'] = MAX_SIZE

path = os.getcwd()
UPLOAD_FOLDER = os.path.join(path, 'uploads')
if not os.path.isdir(UPLOAD_FOLDER):
    os.mkdir(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_first_request
def create_table():
    db.create_all()     # creates all necessary tables automatically


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return func(current_user, *args, **kwargs)

    return decorated


@app.route('/user/signup', methods=['POST'])
@expects_json(register_schema)
def signup():
    try:
        request_data = request.get_json()

        if User.find_by_username(request_data['username']):
            return jsonify({"message": "A user with that username already exists"}), 409

        user_type = request_data.get('type', 'client')
        if user_type not in ['client', 'operation']:
            return jsonify({'message': 'Invalid Type Specified'}), 404

        new_user = User(request_data['username'],
                        generate_password_hash(request_data['password']), user_type, str(uuid.uuid4()))
        new_user.save_to_db()

        return jsonify({'message': 'New user created!'}), 201
    except Exception as ex:
        logging.error(ex)
        return jsonify({'message': 'Some Error occured while creating User. Please try again!!'}), 500


@app.route('/user/login', methods=['GET'])
def login():
    try:
        auth = request.authorization

        if not auth or not auth.username or not auth.password:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        user = User.query.filter_by(username=auth.username).first()

        if not user:
            return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
            ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
            return jsonify({'token': token.decode('UTF-8')}), 200

        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    except Exception as ex:
        logging.error(ex)
        return jsonify({'message': 'Some Error occured while logging in User. Please try again!!'}), 500


@app.route('/file/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    try:
        if current_user.type != 'operation':
            return jsonify({"message": "Not Authorized to access this resource"}), 403

        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            if File.find_by_filename(filename):
                return jsonify({"message": "A file with that filename already exists"}), 409

            new_file = File(filename, str(uuid.uuid4()))
            new_file.save_to_db()
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({'message': 'File Uploaded'}), 200
        else:
            return jsonify({'message': 'Allowed filetypes are: docx, xlsx, pptx'}), 400
    except Exception as ex:
        logging.error(ex)
        return jsonify({'message': 'Some Error occured while uploading file. Please try again!!'}), 500


@app.route('/file/listall', methods=['GET'])
@token_required
def list_files(current_user):
    try:
        if current_user.type != 'client':
            return jsonify({"message": "Not Authorized to access this resource"}), 403
        data = File.find_all_files()
        files = [f.filename for f in data]
        return jsonify({
            'files': files,
            'count': len(files)
        }), 200
    except Exception as ex:
        logging.error(ex)
        return jsonify({'message': 'Some Error occured while uploading file. Please try again!!'}), 500


@app.route('/file/download/<file_name>', methods=['GET'])
@token_required
def download(current_user, file_name):
    try:
        if current_user.type != 'client':
            return jsonify({"message": "Not Authorized to access this resource"}), 403

        file = File.find_by_filename(file_name)
        if not file:
            return jsonify({"message": "File not found"}), 200

        public_id = file.public_id
        return jsonify({
            'download-link': f'{request.host_url}file/{public_id}'
        })
    except Exception as ex:
        logging.error(ex)
        return jsonify({'message': 'Some Error occured while fetching file. Please try again!!'}), 500


@app.route('/file/<public_id>')
@token_required
def get_file(current_user, public_id):
    try:
        if current_user.type != 'client':
            return jsonify({"message": "Not Authorized to access this resource"}), 403

        file = File.find_by_public_id(public_id)
        if not file:
            return jsonify({"message": "File not found"}), 200

        filename = file.filename

        return send_file(f"uploads/{filename}")
    except Exception as ex:
        logging.error(ex)
        return jsonify({'message': 'Some Error occured while downloading file. Please try again!!'}), 500


if __name__ == '__main__':
    db.init_app(app)    # initialises the DB for the app
    app.run(port=5000, debug=True)
