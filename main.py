import hashlib
import uuid

from flask import Flask, render_template, request, make_response, redirect, url_for
from models import User, db

app = Flask(__name__)
db.create_all()


@app.route("/", methods=["GET"])
def index():
    session_token = request.cookies.get("session_token")

    if session_token:
        user = db.query(User).filter_by(session_token=session_token).first()
    else:
        user = None
    return render_template("index.html", user=user)


@app.route("/signup", methods=["POST"])
def signup():
    name = request.form.get("user-name")
    password = request.form.get("user-password")
    password2 = request.form.get("user-password-confirm")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = db.query(User).filter_by(name=name).first()

    if not user:
        if password == password2:
            session_token = str(uuid.uuid4())
            user = User(name=name, password=hashed_password, session_token=session_token)
            db.add(user)
            db.commit()

            response = make_response(redirect(url_for("index")))
            response.set_cookie("session_token", session_token, httponly=True, samesite='Strict')
            return response
        else:
            return render_template("index.html", sign_error="Passwords do not match")
    else:
        return render_template("index.html", sign_error="Username already exists")


@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("user-name")
    password = request.form.get("user-password")
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user = db.query(User).filter_by(name=name).first()

    if not user:
        return render_template("index.html", login_error="User was not found!")
    else:
        if user.password == hashed_password:
            session_token = str(uuid.uuid4())
            user.session_token = session_token

            db.add(user)
            db.commit()

            response = make_response(redirect(url_for("index")))
            response.set_cookie("session_token", session_token, httponly=True, samesite='Strict')
            return response
        else:
            return render_template("index.html", login_error="Incorrect Password")


@app.route('/logout', methods=["GET"])
def logout():
    session_token = request.cookies.get("session_token")

    if session_token:
        response = make_response(redirect(url_for("index")))
        response.set_cookie("session_token", "", expires=0)
        return response
    else:
        return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=True)