from flask import Flask, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import pyotp
import datetime
import re
from sqlalchemy import create_engine
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.pool import StaticPool
from werkzeug.security import generate_password_hash, check_password_hash
import os


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
serializer = URLSafeTimedSerializer(app.secret_key)


# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
# app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
#     "connect_args": {"check_same_thread": False},
#     "poolclass": StaticPool,
# }
db = SQLAlchemy(app)

# Mail config (for Gmail, use an App Password!)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)

mail = Mail(app)

@app.route('/create_db')
def create_db():
    engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
    conn = engine.connect()
    conn.execute("commit")  # required to run CREATE DATABASE outside transactions
    try:
        conn.execute("CREATE DATABASE mfa_app_db;")
    except Exception as e:
        conn.close()
        return f"Error or DB already exists: {e}"
    conn.close()
    return "Database 'mfa_app_db' created successfully!"


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200))
    email = db.Column(db.String(120), unique=True)
    secret = db.Column(db.String(120))
    is_verified = db.Column(db.Boolean, default=False)
    created_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)  # ✅ NEW



class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    success = db.Column(db.Boolean)
    delay = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=db.func.now())


class UserBehaviorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for pre-registration
    username = db.Column(db.String(150))
    email = db.Column(db.String(150))
    event_type = db.Column(db.String(50))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# Create tables and sample user.
def create_tables():
    db.drop_all()
    db.create_all()

    if not User.query.first():
        secret = pyotp.random_base32()
        hashed_password = generate_password_hash("test123")
        test_user = User(
        username="test1",
        password=hashed_password,
        email="testqqq@gmail.com",
        secret=secret
    )

        db.session.add(test_user)
        db.session.commit()
        print(f"Test user created: test / test123 (secret: {secret})")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm = request.form["confirm"]

        # Validate password strength
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*[.!@#$&*])[A-Za-z\d.!@#$&*]{8,}$', password):
            flash(
                "Password must be at least 8 characters long, contain 1 uppercase, 1 lowercase, and 1 special character (.!@#$&*)",
                "warning"
            )

            # Log the behavior
            behavior = UserBehaviorLog(
                username=username.lower(),
                email=email,
                event_type="password_violation",
                details="Password did not meet complexity requirements"
            )
            db.session.add(behavior)

            db.session.commit()

            return render_template("register.html", username=username, email=email)

        # Check password confirmation
        if password != confirm:
            flash("Passwords do not match.", "warning")
            return render_template("register.html", username=username, email=email)

        # Check if username or email already exists
        if User.query.filter_by(username=username.lower()).first():
            flash("Username already exists. Please choose a different username.", "error")
            return render_template("register.html", email=email)

        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please use a different email or login.", "error")
            return render_template("register.html", username=username)

        # Create user
        secret = pyotp.random_base32()
        hashed_password = generate_password_hash(password)
        user = User(
            username=username.lower(),
            email=email,
            password=hashed_password,
            secret=secret,
            is_verified=False
        )

        db.session.add(user)
        try:
            db.session.flush()  # Get user.id before full commit

           # Link past behavior logs by username AND email
            UserBehaviorLog.query.filter_by(
                username=username.lower(),
                email=email,
                user_id=None
            ).update({ 'user_id': user.id })

            # Log successful registration
            behavior = UserBehaviorLog(
                user_id=user.id,
                username=username.lower(),
                email=email,
                event_type="registration_successful",
                details="User successfully registered and verification email sent"
            )
            db.session.add(behavior)


            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while creating your account. Please try again.", "error")
            return render_template("register.html")

        # Generate email verification token and link
        token = serializer.dumps(email, salt='email-verify')
        link = url_for('verify_email', token=token, _external=True)

        # Send verification email
        msg = Message("Email Verification", sender="specialtopics4490@gmail.com", recipients=[email])
        msg.body = f"Click to verify your email: {link}"
        mail.send(msg)

        flash("A verification link has been sent to your email.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")




@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username.lower()).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash("Your email is not verified. Please verify your email before logging in.", "error")
                return render_template("login.html")

            # Check if user has a previous successful login
            last_success_log = (
                LoginLog.query
                .filter_by(user_id=user.id, success=True)
                .order_by(LoginLog.timestamp.desc())
                .first()
            )

            if last_success_log:
                return render_template("success.html", time=round(last_success_log.delay, 2), username=user.username)

            # No previous successful login, proceed with OTP
            session["user_id"] = user.id
            session["start_time"] = datetime.datetime.now().isoformat()

            totp = pyotp.TOTP(user.secret)
            otp_code = totp.now()
            session["otp_code"] = otp_code

            msg = Message("Your OTP Code", sender="noreply@example.com", recipients=[user.email])
            msg.body = f"Your OTP code is: {otp_code}"
            mail.send(msg)

            return redirect("/verify")
        else:
            # Only log failed login if the user exists (i.e. is a registered user)
            if user:
                behavior = UserBehaviorLog(
                user_id=user.id,  # ✅ This line adds user_id to the entry
                username=username.lower(),
                email=user.email,
                event_type="login_failed",
                details="Invalid password for registered user"
            )

                db.session.add(behavior)
                db.session.commit()

            flash("Invalid username or password", "error")

    return render_template("login.html")




# OTP verification route

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        entered_otp = request.form["otp"]
        correct_otp = session.get("otp_code")
        user_id = session.get("user_id")

        user = db.session.get(User, user_id)

        if entered_otp == correct_otp:
            delay = (datetime.datetime.now() - datetime.datetime.fromisoformat(session["start_time"])).total_seconds()
            log = LoginLog(user_id=user_id, success=True, delay=delay)
            db.session.add(log)
            db.session.commit()

            # ✅ Stop counting after success
            session["incorrect_otp_attempts"] = 0

            session["login_delay"] = round(delay, 2)
            session["username"] = user.username
            return redirect(url_for("success"))

        else:
            # Log incorrect OTP attempt

            behavior = UserBehaviorLog(
            user_id=user.id,  # <-- Add thiss
            username=user.username,
            email=user.email,
            event_type="otp_failed",
            details="Incorrect OTP entered"
        )


            db.session.add(behavior)
            db.session.commit()

            # # ✅ Track incorrect OTP attempts
            # session["incorrect_otp_attempts"] = session.get("incorrect_otp_attempts", 0) + 1
            # flash(f"Invalid OTP. Attempt #{session['incorrect_otp_attempts']}", "error")

    return render_template("otp.html")


@app.route("/success")
def success():
    # Retrieve data from session
    time = session.pop("login_delay", None)
    username = session.pop("username", None)

    if time is None or username is None:
        # If data not found, redirect to login or somewhere safe
        return redirect(url_for("login"))

    return render_template("success.html", time=time, username=username)



@app.route("/verify_email/<token>")
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=600)  # 10 minutes expiration
    except:
        flash("Verification link expired or invalid.", "error")
        return redirect("/login")

    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()

        # Auto-login after verification
        session["user_id"] = user.id
        session["start_time"] = datetime.datetime.now().isoformat()

        # Generate OTP
        totp = pyotp.TOTP(user.secret)
        otp_code = totp.now()
        session["otp_code"] = otp_code

        # Send OTP
        msg = Message("Your OTP Code", sender="specialtopics4490@gmail.com", recipients=[user.email])
        msg.body = f"Your OTP code is: {otp_code}"
        mail.send(msg)
        flash("Email verified successfully! Please log in.", "success")
        return redirect("/")

    flash("User not found.", "error")
    return redirect("/login")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for("login"))

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

if __name__ == "__main__":
    with app.app_context():
        create_tables()
    app.run(debug=True, threaded=False)

