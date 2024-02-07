from flask import Flask, request, jsonify, make_response, send_file
from flask_expects_json import expects_json
from jsonschema import ValidationError
from werkzeug.utils import secure_filename

from flask_sqlalchemy import SQLAlchemy

from sqlalchemy import func
from sqlalchemy.types import UserDefinedType
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import expression

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

import jwt
from secret import JWT_KEY

from secrets import token_urlsafe

import datetime
import time

import enum

import base64
from PIL import Image
import os
from io import BytesIO

from waitress import serve

import dill as pickle
import pandas as pd

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:root@localhost/weather_app"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = "uploads"
app.config['DATASET_FOLDER'] = "datasets"
app.config['GRAPH_FOLDER'] = "graphs"

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

    try:
        payload = jwt.decode(token, JWT_KEY, algorithms="HS256")
    except:
        payload = None

    if not payload: return None

    user = User.query.filter_by(name=payload["name"]).first()
    if user:
        return user
    else:
        return None


register_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string', 'maxLength': 20, 'minLength': 1, 'pattern': '^[A-Za-z0-9_]*$'},
        'password': {'type': 'string', 'maxLength': 20, 'minLength': 5, 'pattern': '^[A-Za-z0-9@$!%*#?&]*$'},
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

        new_user = User(name=name, password=ph.hash(password))

        db.session.add(new_user)
        db.session.commit()

        return jsonify({"status": True}), 200

    return jsonify({"error": "name"}), 409


login_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string', 'maxLength': 20, 'minLength': 1, 'pattern': '^[A-Za-z0-9_]*$'},
        'password': {'type': 'string', 'maxLength': 20, 'minLength': 5, 'pattern': '^[A-Za-z0-9@$!%*#?&]*$'}
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
        token = jwt.encode({"name": user.name, "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(weeks=1)}, JWT_KEY)

        return jsonify({"token": token}), 200
    return jsonify({"error": "name or password"}), 403


# no longer needed because we use jwt

# @app.route("/logout", methods = ['POST'])
# def logout_():
#     user = user_from_token()

#     if user:
#         user.token = None
#         db.session.commit()

#         return jsonify({"status": True}), 200
#     else:
#         return jsonify({"error": "token"}), 401


# --------------------
# FILE MANAGEMENT
# --------------------


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['csv', 'xlsx']


upload_schema = {
    'type': 'object',
    'properties': {
        'filename': {'type': 'string'}
    },
    'required': ['filename']
}


@app.route('/upload', methods=['POST', 'DELETE'])
@expects_json(upload_schema, ignore_for=['POST'])
def upload_():
    user = user_from_token()

    if not user:
        return jsonify({"error": "token"}), 401

    file_dir = os.path.join(app.config['UPLOAD_FOLDER'], user.name, app.config['DATASET_FOLDER'])

    if request.method == 'POST':

        # TODO: check if the file is not over the size limit
        if os.path.exists(file_dir):
            dir_size = sum(d.stat().st_size for d in os.scandir(file_dir) if d.is_file())
            if dir_size > 10*1024*1024*1024:
                return jsonify({"error": "file size"}), 400

        if 'file' not in request.files:
            return jsonify({"error": "file"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "filename"}), 400
        if file and allowed_file(file.filename):
            if not os.path.exists(file_dir):
                os.makedirs(file_dir)

            filename = secure_filename(file.filename)
            file_dir = os.path.join(file_dir, filename)
            file.save(file_dir) # TODO: figure out how to encrypt this

            return jsonify({"status": True})
        return jsonify({"error": "ext"}), 400

    elif request.method == 'DELETE':
        filename = request.json.get("filename")
        filename = secure_filename(filename)
        file_dir = os.path.join(file_dir, filename)

        try:
            os.remove(file_dir)
        except OSError:
            return jsonify({"error": "os error"}), 500

        return jsonify({"status": True})


@app.route("/uploads")
def uploads_():
    user = user_from_token()

    if not user:
        return jsonify({"error": "token"}), 401

    file_dir = os.path.join(app.config['UPLOAD_FOLDER'], user.name, app.config['DATASET_FOLDER'])
    files = os.listdir(file_dir)

    return jsonify({"files": files}), 200


graph_types = ["analyze_1", "trend_1", "predict_1"] # feel free to add more graph types or change the current ones


@app.route("/graph")
def graph_():
    user = user_from_token()

    if not user:
        return jsonify({"error": "token"}), 401

    graph_type = request.args.get('type', type=str)

    if not graph_type in graph_types:
        return jsonify({"error": "graph type"}), 400

    file_dir = os.path.join(app.config['UPLOAD_FOLDER'], user.name, app.config['GRAPH_FOLDER'], graph_type)
    if not os.path.exists(file_dir):
        return jsonify({"error": "no file"}), 400

    return send_file(file_dir)

# --------------------
# ANALYZE, TRENDS, PREDICT
# --------------------


@app.route("/analyze")
def analyze_():
    user = user_from_token()

    if not user:
        return jsonify({"error": "token"}), 401

    time_interval_from = request.args.get('from', type=int) # unix
    time_interval_to = request.args.get('to', type=int) # unix
    filename = request.args.get('filename', type=str)

    filename = secure_filename(filename)

    file_dir = os.path.join(app.config['UPLOAD_FOLDER'], user.name, app.config['DATASET_FOLDER'], filename)
    if not os.path.exists(file_dir):
        return jsonify({"error": "no file"}), 400

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
    # filepath variable: file_dir

    # --------------------
    # --------------------


    graph_file_path = os.path.join(app.config['UPLOAD_FOLDER'], user.name, app.config['GRAPH_FOLDER'], 'analyze_1.png')

    return jsonify(result_metrics), 200



   
with open('models/model_te/fb_model_te.h5py', 'rb') as f:
    fb_te = pickle.load(f)
with open('models/model_te/model_te.h5py', 'rb') as f:
    model_te = pickle.load(f)


def f_te(end_time):
    global fb_te, model_te
    start = '2022-12-31'
     
    start = datetime.datetime.strptime(start, '%Y-%m-%d')
    end = datetime.datetime.strptime(end_time, '%Y-%m-%d')   
    
    daterange = [(start + datetime.timedelta(days=x)).strftime('%Y-%m-%d') for x in range(0, (end-start).days)]
    new_test_series = pd.DataFrame(pd.to_datetime(daterange), columns=['ds'])
    
    predictions = fb_te.make_future_dataframe(periods=len(new_test_series), freq='D')
    forecast = fb_te.predict(predictions)
    
    test_gbt = new_test_series.merge(forecast, on='ds', how='left')
    
    return model_te.predict(test_gbt)
    

with open('models/model_os/fb_model_os.h5py', 'rb') as f:
    fb_os = pickle.load(f)
with open('models/model_os/model_os.h5py', 'rb') as f:
    model_os = pickle.load(f)


def f_os(end_time):
    global fb_os, model_os
    start = '2022-12-31'
    
    
    start = datetime.datetime.strptime(start, '%Y-%m-%d')
    end = datetime.datetime.strptime(end_time, '%Y-%m-%d')   
    
    daterange = [(start + datetime.timedelta(days=x)).strftime('%Y-%m-%d') for x in range(0, (end-start).days)]
    new_test_series = pd.DataFrame(pd.to_datetime(daterange), columns=['ds'])
    
    predictions = fb_os.make_future_dataframe(periods=len(new_test_series), freq='D')
    forecast = fb_os.predict(predictions)
    
    test_gbt = new_test_series.merge(forecast, on='ds', how='left')
    
    return model_os.predict(test_gbt)
    


with open('models/model_vt/fb_model_vt.h5py', 'rb') as f:
    fb_vt = pickle.load(f)
with open('models/model_vt/model_vt.h5py', 'rb') as f:
    model_vt = pickle.load(f)


def f_vt(end_time):
    global fb_vt, model_vt
    start = '2022-12-31'
     
    start = datetime.datetime.strptime(start, '%Y-%m-%d')
    end = datetime.datetime.strptime(end_time, '%Y-%m-%d')   
    
    daterange = [(start + datetime.timedelta(days=x)).strftime('%Y-%m-%d') for x in range(0, (end-start).days)]
    new_test_series = pd.DataFrame(pd.to_datetime(daterange), columns=['ds'])
    
    predictions = fb_vt.make_future_dataframe(periods=len(new_test_series), freq='D')
    forecast = fb_vt.predict(predictions)
    
    test_gbt = new_test_series.merge(forecast, on='ds', how='left')
    
    return model_vt.predict(test_gbt)


with open('models/model_wl/fb_model_wl.h5py', 'rb') as f:
    fb_wl = pickle.load(f)
with open('models/model_wl/model_wl.h5py', 'rb') as f:
    model_wl = pickle.load(f)


def f_wl(end_time):
    global fb_wl, model_wl
    start = '2022-12-31'
     
    start = datetime.datetime.strptime(start, '%Y-%m-%d')
    end = datetime.datetime.strptime(end_time, '%Y-%m-%d')   
    
    daterange = [(start + datetime.timedelta(days=x)).strftime('%Y-%m-%d') for x in range(0, (end-start).days)]
    new_test_series = pd.DataFrame(pd.to_datetime(daterange), columns=['ds'])
    
    predictions = fb_wl.make_future_dataframe(periods=len(new_test_series), freq='D')
    forecast = fb_wl.predict(predictions)
    
    test_gbt = new_test_series.merge(forecast, on='ds', how='left')
    
    return model_wl.predict(test_gbt)


predict_schema = {
    'type': 'object',
    'properties': {
        'days': {'type': 'number'}
    },
    'required': ['days']
}


@app.route('/predict', methods=['POST'])
@expects_json(predict_schema)
def predict_():
    user = user_from_token()

    if not user:
        return jsonify({"error": "token"}), 401

    time = request.json.get("days")

    # --------------------
    # --------------------

    prediction_result = {
        "volume": 0,
        "wetness": 0,
        "wind_speed": 0,
        "temp": 0,
    }

    prediction_days = []

    end = '2023-01-0' + str(max(min(time, 7), 1))

    te = f_te(end)
    os = f_os(end)
    vt = f_vt(end)
    wl = f_wl(end)

    for i in range(len(te)):
        pred = prediction_result.copy()
        pred["temp"] = te[i]
        pred["volume"] = os[i]
        pred["wind_speed"] = vt[i]
        pred["wetness"] = wl[i]
        prediction_days.append(pred)
    

    # --------------------
    # --------------------

    return jsonify({"days": prediction_days}), 200


if __name__ == "__main__":
    # serve(app, host='localhost', port=3333) 
    app.run(debug=True)