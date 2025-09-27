from flask import Flask, render_template, request, jsonify, redirect, url_for, flash 
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from datetime import datetime, timedelta
import re
import config
import requests
import os
from bson.objectid import ObjectId
from email_validator import validate_email, EmailNotValidError 
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash


# Init app
app = Flask(__name__)
app.config["MONGO_URI"] = config.MONGO_URI
app.config["JWT_SECRET_KEY"] = config.JWT_SECRET_KEY
app.config["SECRET_KEY"] = config.SECRET_KEY

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

USERS = mongo.db.users

# Constants
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# Helpers
def is_strong_password(pw: str) -> bool:
    # at least 8 chars, has letter, number and special char
    return bool(re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$', pw))

def verify_recaptcha(token: str) -> bool:
    # If no keys configured, skip (development)
    if not config.RECAPTCHA_SECRET_KEY:
        return True
    payload = {
        "secret": config.RECAPTCHA_SECRET_KEY,
        "response": token
    }
    try:
        res = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload, timeout=5)
        j = res.json()
        return j.get("success", False)
    except Exception:
        return False

def user_locked(user_doc):
    lock_until = user_doc.get("lock_until")
    if not lock_until:
        return False
    try:
        lock_dt = datetime.fromisoformat(lock_until)
        return datetime.utcnow() < lock_dt
    except Exception:
        return False

def increment_failed_login(email):
    user = USERS.find_one({"email": email})
    if not user:
        return
    failed = user.get("failed_attempts", 0) + 1
    updates = {"failed_attempts": failed}
    if failed >= MAX_FAILED_ATTEMPTS:
        lock_dt = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        updates["lock_until"] = lock_dt.isoformat()
    USERS.update_one({"_id": user["_id"]}, {"$set": updates})

def reset_failed_login(email):
    USERS.update_one({"email": email}, {"$set": {"failed_attempts": 0, "lock_until": None}})

# Routes
@app.route("/")
def index():
    return render_template("index.html", recaptcha_site_key=config.RECAPTCHA_SITE_KEY)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", recaptcha_site_key=config.RECAPTCHA_SITE_KEY)
    # POST
    data = request.form
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role = data.get("role", "User")
    recaptcha_token = data.get("g-recaptcha-response", "")

    # Basic checks
    if not username or not email or not password:
        flash("All fields are required", "error")
        return redirect(url_for("register"))

    try:
        validate_email(email)
    except EmailNotValidError as e:
        flash(str(e), "error")
        return redirect(url_for("register"))

    if not is_strong_password(password):
        flash("Password must be at least 8 chars long and include letters, numbers and special chars", "error")
        return redirect(url_for("register"))

    if not verify_recaptcha(recaptcha_token):
        flash("reCAPTCHA verification failed. Try again.", "error")
        return redirect(url_for("register"))

    # Check duplicate
    if USERS.find_one({"email": email}):
        flash("Email already registered", "error")
        return redirect(url_for("register"))

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user_doc = {
        "username": username,
        "email": email,
        "password": pw_hash,
        "role": role,
        "created_at": datetime.utcnow(),
        "failed_attempts": 0,
        "lock_until": None
    }
    USERS.insert_one(user_doc)
    flash("Registered successfully. Please login.", "success")
    return redirect(url_for("login"))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Show the login page
        return render_template('login.html')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # validate user from DB (example)
        user = mongo.db.users.find_one({"email": email})
        if user and check_password_hash(user['password'], password):
            # login success
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))  # or wherever
        else:
            flash("Invalid email or password", "danger")
            return redirect(url_for('login'))


@app.route("/admin")
@jwt_required(locations=["query_string"])
def admin_dashboard():
    # token passed in query ?token=...
    current = get_jwt_identity()
    if not current or current.get("role") != "Admin":
        return "Forbidden", 403
    users = list(USERS.find({}, {"password": 0}))
    # Convert ObjectId and datetimes
    for u in users:
        u["_id"] = str(u["_id"])
        if isinstance(u.get("created_at"), datetime):
            u["created_at"] = u["created_at"].isoformat()
    return render_template("admin.html", users=users, current=current)

@app.route('/user', methods=['GET'])
def get_user():
    # 1. First check if token is in query params
    token = request.args.get('jwt') or request.args.get('token')

    if token:
        try:
            # Manually verify JWT if passed via query string
            verify_jwt_in_request(optional=True)
            user_identity = get_jwt_identity()
            return jsonify(user_identity), 200
        except Exception as e:
            return jsonify({"msg": f"Invalid token: {str(e)}"}), 401

    # 2. If no query param, check Authorization header
    try:
        verify_jwt_in_request()
        user_identity = get_jwt_identity()
        return jsonify(user_identity), 200
    except Exception as e:
        return jsonify({"msg": "Missing or invalid token", "error": str(e)}), 401

@app.route("/admin/delete/<user_id>", methods=["POST"])
@jwt_required(locations=["query_string"])
def admin_delete_user(user_id):
    current = get_jwt_identity()
    if not current or current.get("role") != "Admin":
        return "Forbidden", 403
    # Do not allow admin to delete themselves
    if user_id == current.get("id"):
        flash("You cannot delete your own admin account.", "error")
        return redirect(url_for("admin_dashboard", token=request.args.get("token")))
    USERS.delete_one({"_id": ObjectId(user_id)})
    flash("User deleted", "success")
    return redirect(url_for("admin_dashboard", token=request.args.get("token")))

@app.route("/profile/<user_id>")
def profile(user_id):
    u = USERS.find_one({"_id": ObjectId(user_id)}, {"password": 0})
    if not u:
        return "User not found", 404
    u["_id"] = str(u["_id"])
    return jsonify(u)

# Simple API health check
@app.route("/health")
def health():
    try:
        mongo.cx.admin.command("ping")
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

if __name__ == "__main__":
    # In production, use a proper server like gunicorn
    app.run(debug=True)
