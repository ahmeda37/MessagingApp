import hashlib
import uuid

from flask import Flask, render_template, request, make_response, redirect, url_for
from models import User, Message, db

app = Flask(__name__)
db.create_all()

# Route Handles the homepage
@app.route("/", methods=["GET"])
def index():
    # Get the session_token to check if user is signed im
    session_token = request.cookies.get("session_token")

    # If session_token, get the user and messages from the database
    if session_token:
        user = db.query(User).filter_by(session_token=session_token).first()
        messages = db.query(Message).filter_by(receiver=user.id).all()
    # Else set user and messages to none
    else:
        user = None
        messages = None
    # render_template for Index HTML and pass user and messages variables.
    return render_template("index.html", user=user, messages=messages)


# Route Handles a User wanting to sign up to your website
@app.route("/signup", methods=["POST"])
def signup():
    # GET all values from form including user-name, user-password and user-password-confirm
    name = request.form.get("user-name")
    password = request.form.get("user-password")
    password2 = request.form.get("user-password-confirm")

    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Check is the user already exists in the database
    user = db.query(User).filter_by(name=name).first()

    # If a user is not found
    if not user:
        # If the password matches the confirmed-password
        if password == password2:
            # Create a new session_token
            session_token = str(uuid.uuid4())
            # Create a new user object
            user = User(name=name, password=hashed_password, session_token=session_token)

            # Add and commit to database
            db.add(user)
            db.commit()

            # Use make response to set a cookie containing the session_token
            response = make_response(redirect(url_for("index")))
            response.set_cookie("session_token", session_token, httponly=True, samesite='Strict')

            # Return response
            return response

        # Else - the passwords do not match
        else:
            # Just return the the index page
            return render_template("index.html", sign_error="Passwords do not match")
    # Else - a user already exists
    else:
        # Just return the index page
        return render_template("index.html", sign_error="Username already exists")


# Handles a return user signing into their account
@app.route("/login", methods=["POST"])
def login():
    # Get all the values from the from including user-name, user-password
    name = request.form.get("user-name")
    password = request.form.get("user-password")

    # Hash the password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Get the user from the database
    user = db.query(User).filter_by(name=name).first()

    # If no user is found
    if not user:
        # Just return the index page
        return render_template("index.html", login_error="User was not found!")

    # Else - User is found
    else:
        # If the hashed password matches the database password
        if user.password == hashed_password:

            # Create a new session_token
            session_token = str(uuid.uuid4())

            # Update the user object with the new session token
            user.session_token = session_token

            # Save changes to the database
            db.add(user)
            db.commit()

            # Use make response to send the user back to the index page with a cookies containing the session_token
            response = make_response(redirect(url_for("index")))
            response.set_cookie("session_token", session_token, httponly=True, samesite='Strict')
            return response

        # Else - The user enter the wrong password
        else:
            # Just return the index page
            return render_template("index.html", login_error="Incorrect Password")


# The route handles users wanting to logout of the website
@app.route('/logout', methods=["GET"])
def logout():
    # Get the session_token
    session_token = request.cookies.get("session_token")

    # If session_token is found
    if session_token:

        # Use make response to send the user to the index page and set empty cookie with expiry
        response = make_response(redirect(url_for("index")))
        response.set_cookie("session_token", "", expires=0)
        return response

    # Else - no session_token
    else:

        # Just send the user to the index page
        return redirect(url_for("index"))


# This route handles sending messages
@app.route('/send', methods=["GET", "POST"])
def send():

    # Get the session_token
    session_token = request.cookies.get("session_token")

    # If session_token found
    if session_token:

        # Get the user from the database
        user = db.query(User).filter_by(session_token=session_token).first()

        # If get request -- i.e we just show the user the messages page
        if request.method == "GET":

            # Get all the users in the database
            users = db.query(User).all()

            # Send the user to the send html page, set user and users in return
            return render_template("send.html", user=user, users=users)

        # ELIF - post request
        elif request.method == "POST":

            # GET the receiver and message_body from the form
            receiver = request.form.get("receiver")
            message_body = request.form.get("message-body")

            # Get the receiver from the database
            rec_user = db.query(User).filter_by(name=receiver).first()

            # If receiver is found
            if rec_user:

                # Create a message object and set the send, receiver and message
                message = Message(sender=user.id, receiver=rec_user.id, message=message_body)

                # Save the message object to the database
                db.add(message)
                db.commit()

                # Send the user back to the index page
                return redirect(url_for("index"))

            # Else - receiver was not found
            else:

                # Send the user to the index page
                return redirect(url_for("index"))
        # Else - not a get or post request
        else:

            # Send the user to the index page
            return redirect(url_for("index"))
    # Else - no session_token found
    else:

        # Send the user to the index page
        return redirect(url_for("index"))


# This route handles deleting messages
@app.route("/delete/<msg_id>", methods=["GET"])
def delete(msg_id):
    # Get session_token
    session_token = request.cookies.get("session_token")

    # Get the user from the database
    user = db.query(User).filter_by(session_token=session_token).first()

    # Get the message using msg_id from database
    message = db.query(Message).get(int(msg_id))

    # If the user.id matchs the message.receiver
    if user.id == message.receiver:

        # Delete the message from the database
        db.delete(message)
        db.commit()

        # Send the user to the index page
        return redirect(url_for("index"))

    # Else - the message does not belong to the user
    else:

        # Send the user to the index page
        return redirect(url_for("index"))


if __name__ == '__main__':
    app.run(debug=True)