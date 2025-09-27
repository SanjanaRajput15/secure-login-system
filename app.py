from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
)
from datetime import datetime, timedelta
import re
import config
import requests
from bson.objectid import ObjectId
from email_validator import validate_email, EmailNotValidError

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
    return bool(re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$', pw))

def verify_recaptcha(token: str) -> bool:
    if not config.RECAPTCHA_SECRET_KEY:
        return True
    payload = {"secret": config.RECAPTCHA_SECRET_KEY, "response": token}
    try:
        res = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload, timeout=5)
        return res.json().get("success", False)
    except Exception:
        return False

def user_locked(user_doc):
    lock_until = user_doc.get("lock_until")
    if not lock_until:
        return False
    try:
        return datetime.utcnow() < datetime.fromisoformat(lock_until)
    except Exception:
        return False

def increment_failed_login(email):
    user = USERS.find_one({"email": email})
    if not user:
        return
    failed = user.get("failed_attempts", 0) + 1
    updates = {"failed_attempts": failed}
    if failed >= MAX_FAILED_ATTEMPTS:
        updates["lock_until"] = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
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

    data = request.form
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role = data.get("role", "User")
    recaptcha_token = data.get("g-recaptcha-response", "")

    # Validations
    if not username or not email or not password:
        flash("All fields are required", "error")
        return redirect(url_for("register"))
    try:
        validate_email(email)
    except EmailNotValidError as e:
        flash(str(e), "error")
        return redirect(url_for("register"))
    if not is_strong_password(password):
        flash("Password must be 8+ chars and include letters, numbers, special chars", "error")
        return redirect(url_for("register"))
    if not verify_recaptcha(recaptcha_token):
        flash("reCAPTCHA verification failed", "error")
        return redirect(url_for("register"))
    if USERS.find_one({"email": email}):
        flash("Email already registered", "error")
        return redirect(url_for("register"))

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    USERS.insert_one({
        "username": username,
        "email": email,
        "password": pw_hash,
        "role": role,
        "created_at": datetime.utcnow(),
        "failed_attempts": 0,
        "lock_until": None
    })
    flash("Registered successfully. Please login.", "success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email").strip().lower()
    password = request.form.get("password")
    user = USERS.find_one({"email": email})

    if not user:
        flash("Invalid email or password", "danger")
        return redirect(url_for("login"))

    if user_locked(user):
        flash("Account locked due to multiple failed attempts. Try later.", "danger")
        return redirect(url_for("login"))

    if bcrypt.check_password_hash(user["password"], password):
        reset_failed_login(email)
        access_token = create_access_token(identity={
            "id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        })
        flash("Login successful!", "success")
        if user["role"] == "Admin":
            return redirect(url_for("admin_dashboard", token=access_token))
        else:
            return redirect(url_for("dashboard", token=access_token))
    else:
        increment_failed_login(email)
        flash("Invalid email or password", "danger")
        return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    try:
        verify_jwt_in_request(locations=["query_string"])
        user = get_jwt_identity()
    except Exception:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=user.get("username"))

@app.route("/admin")
def admin_dashboard():
    try:
        verify_jwt_in_request(locations=["query_string"])
        current = get_jwt_identity()
    except Exception:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if current.get("role") != "Admin":
        return "Forbidden", 403

    users = list(USERS.find({}, {"password": 0}))
    for u in users:
        u["_id"] = str(u["_id"])
        if isinstance(u.get("created_at"), datetime):
            u["created_at"] = u["created_at"].isoformat()

    return render_template("admin.html", users=users, current=current)

@app.route("/admin/delete/<user_id>", methods=["POST"])
def admin_delete_user(user_id):
    try:
        verify_jwt_in_request(locations=["query_string"])
        current = get_jwt_identity()
    except Exception:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    if current.get("role") != "Admin":
        return "Forbidden", 403

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

@app.route("/health")
def health():
    try:
        mongo.cx.admin.command("ping")
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

@app.route("/logout")
def logout():
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
