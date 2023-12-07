from flask import Flask, request, jsonify, make_response, send_file
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
# app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
# app.config['UPLOAD_FOLDER'] = "uploads"

app.debug = True

db = SQLAlchemy(app)

BaseModel = db.Model

app.app_context().push()

ph = PasswordHasher()

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