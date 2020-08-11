from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.dialects.mysql import LONGTEXT
import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(94))
    perfil = db.Column(db.String(50))
    create_date = db.Column(db.DateTime, default = datetime.datetime.now)

    def __init__(self, username, password, perfil):
        self.username = username
        self.password = self.__create_password(password)
        self.perfil = perfil

    def __create_password(self, password):
        return generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

class Archivos(db.Model):
    __tablename__='archivos'
    id = db.Column(db.Integer,primary_key = True)
    nombre=db.Column(db.String(50), unique=True)
    correos=db.Column(db.String(50), unique=True)
    ldap=db.Column(db.String(50), unique=True)
    Fecha = db.Column(db.DateTime, default = datetime.datetime.now)
