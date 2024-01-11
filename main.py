from flask import Flask, request, jsonify, make_response, send_file, secure_filename
from flask_expects_json import expects_json
from jsonschema import ValidationError

from flask_sqlalchemy import SQLAlchemy

from sqlalchemy import func
from sqlalchemy.types import UserDefinedType
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import expression

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from secrets import token_urlsafe

import datetime
import time

import enum

import base64
from PIL import Image
import os
from io import BytesIO

from waitress import serve

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:root@localhost/weather-app"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = "uploads"

app.debug = True

db = SQLAlchemy(app)

BaseModel = db.Model

app.app_context().push()

ph = PasswordHasher()


@app.errorhandler(400)
def bad_request(error):
    print(error)
    if isinstance(error.description, ValidationError):
        original_error = error.description
        return make_response(jsonify({"error": original_error.message}), 400)
    # handle other "Bad Request"-errors
    return error

@app.after_request
def after(response):
    print(response.get_data())
    return response


def unixify(time_to_unixify):
    if time_to_unixify == None: return None
    return datetime.datetime.timestamp(time_to_unixify)*1000


class utcnow(expression.FunctionElement):
    type = db.DateTime()
    inherit_cache = True


@compiles(utcnow, 'mysql')
def my_utcnow(element, compiler, **kw):
    return "(UTC_TIMESTAMP)"


class User(BaseModel):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column("name", db.String(20), nullable=False, unique=True)
    password = db.Column("password", db.CHAR(97), nullable=False)
    token = db.Column("token", db.CHAR(43))


    @property
    def serialize(self):
        return {
           'id': self.id,
           'name': self.name,
        }


db.create_all()

# --------------------
# --------------------
#
# TODOS
#
# TODO: probably change request.json to request.form (depends on the front end impl)
# TODO: argon2 encrypt the token
# TODO: figure out exports (PDF, CSV, excel?)
# TODO: figure out how to set up a reverse proxy (for my 1 GB timeweb server)
# --------------------
# --------------------


# --------------------
# USER SYSTEM
# --------------------


def user_from_token(): 
    token = request.headers['x-token']

    print(token)

    user = User.query.filter_by(token=token).first()
    if user:
        return user
    else:
        return None


register_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string', 'maxLength': 20, 'minLength': 1, 'pattern': '^["A-Za-z0-9_]*$'},
        'password': {'type': 'string', 'maxLength': 20, 'minLength': 5, 'pattern': '^["A-Za-z0-9 !"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~"]*$'},
    },
    'required': ['name', 'password']
}


@app.route("/register", methods = ['POST'])
@expects_json(register_schema)
def register_():
    name = request.json.get("name")

    user_exists = db.session.query(User.query.filter(User.name == name).exists()).scalar()

    if not user_exists:
        password = request.json.get("password")

        new_user = UserReq(name=name, password=ph.hash(password))

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"status": True}), 200

    return jsonify({"error": "name"}), 409


login_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string', 'maxLength': 20, 'minLength': 1, 'pattern': '^["A-Za-z0-9_]*$'},
        'password': {'type': 'string', 'maxLength': 20, 'minLength': 5, 'pattern': '^["A-Za-z0-9 !"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~"]*$'}
    },
    'required': ['name', 'password']
}


@app.route("/login", methods = ['POST'])
@expects_json(login_schema)
def login_():
    name = request.json.get("name")
    password = request.json.get("password")

    user = User.query.filter_by(name=name).first()

    if not user:
        return jsonify({"error": "name or password"}), 403

    password_result = False

    try:
        password_result = ph.verify(user.password, password)
    except VerifyMismatchError:
        pass

    if password_result:
        user.token = token_urlsafe()
        db.session.commit()
        user_dict = {
            "user": user.serialize
        }
        user_dict['token'] = user.token
        return jsonify(user_dict), 200
    return jsonify({"error": "name or password"}), 403


@app.route("/logout", methods = ['POST'])
def logout_():
    user = user_from_token()

    if user:
        user.token = None
        db.session.commit()

        return jsonify({"status": True}), 200
    else:
        return jsonify({"error": "token"}), 401


# --------------------
# FILE MANAGEMENT
# --------------------


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['csv', 'xlsx']


@app.route('/upload', methods=['POST'])
def upload_file_():
    user = user_from_token()

    if not user:
        return jsonify({"error": "token"}), 401

    # TODO: check if the file is not over the size limit

    if 'file' not in request.files:
        return jsonify({"error": "file"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "filename"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_dir = os.path.join(app.config['UPLOAD_FOLDER'], user.name)
        if not os.path.exists(file_dir):
            os.makedirs(file_dir)
        file_dir = os.path.join(file_dir, filename)
        file.save(file_dir) # TODO: figure out how to encrypt this

        return jsonify({"status": True})


# --------------------
# ANALYZE 
# --------------------


@app.route("/analyze")
def analyze_():
    time_interval_from = request.args.get('from', type=int) # unix
    time_interval_to = request.args.get('to', type=int) # unix

    if time_interval_from > time_interval_to:
        return jsonify({"error": "interval"}), 400

    # --------------------
    # --------------------

    result_metrics = {
        "average_temp": 0,
        "highest_temp": 0,
        "lowest_temp": 0,
    }

    # TODO: analyze

    # --------------------
    # --------------------

    # TODO would also return visualisation? figure out how we are going to send that.
    return jsonify(result_metrics), 200


@app.route("/predict")
def predict_():
    time = request.args.get('time', type=int) # unix

    # --------------------
    # --------------------

    prediction_result = {
        "temp": 0,
        "weather": "",
    }

    # TODO: predict

    # --------------------
    # --------------------

    return jsonify(prediction_result), 200


if __name__ == "__main__":
    # serve(app, host='localhost', port=3333) 
    app.run(debug=True)