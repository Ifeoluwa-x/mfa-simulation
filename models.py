from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True)
    secret = db.Column(db.String(120))  # TOTP secret key

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    success = db.Column(db.Boolean)
    delay = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=db.func.now())
