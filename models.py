import os
from sqla_wrapper import SQLAlchemy

db = SQLAlchemy(os.getenv("DATABASE_URL", "sqlite:///localhost.sqlite"))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    session_token = db.Column(db.String)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.Integer, db.ForeignKey('users.id'))
    receiver = db.Column(db.Integer, db.ForeignKey('users.id'))
    message = db.Column(db.String)
    s = db.relationship("User", foreign_keys=[sender])
    r = db.relationship("User", foreign_keys=[receiver])