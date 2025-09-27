from flask import Flask, render_template, request, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import re
import json
import config

# ---- Init app ----
app = Flask(__name__)
app.config["MONGO_URI"] = config.MONGO_URI
app.config["JWT_SECRET_KEY"] = config.JWT_SECRET_KEY
app.config["SECRET_KEY"] = config.SECRET_KEY

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

USERS = mongo.db.users

# ---- Helpers ----
def is_strong_password(pw: str) -> bool:
    return bool(re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$', pw))

# ---- Routes ----
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    
    data = request.form
    username = data.get("username").strip()
    email = data.get("email").strip().lower()
    password = data.get("password")
    role = data.get("role", "User")

    if not username or not email or not password:
        flash("All fields are required", "error")
        return redirect(url_for("register"))

    if not is_strong_password(password):
        flash("Password must be 8+ chars, letters, numbers & special char", "error")
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
        "created_at": datetime.utcnow()
    })

    flash("Registered successfully! Please login.", "success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    
    email = request.form.get("email").strip().lower()
    password = request.form.get("password")
    user = USERS.find_one({"email": email})

    if user and bcrypt.check_password_hash(user["password"], password):
        # Create JWT token with JSON string as identity
        access_token = create_access_token(identity=json.dumps({
            "id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }), expires_delta=timedelta(hours=1))
        
        resp = redirect(url_for("dashboard"))
        resp.set_cookie("access_token_cookie", access_token, httponly=True, samesite='Lax')
        flash("Login successful!", "success")
        return resp
    else:
        flash("Invalid email or password", "error")
        return redirect(url_for("login"))

@app.route("/dashboard")
@jwt_required(locations=["cookies"])
def dashboard():
    user = json.loads(get_jwt_identity())
    if user["role"] == "Admin":
        return redirect(url_for("admin_dashboard"))
    return render_template("dashboard.html", username=user["username"], role=user["role"])

@app.route("/admin")
@jwt_required(locations=["cookies"])
def admin_dashboard():
    user = json.loads(get_jwt_identity())
    if user["role"] != "Admin":
        return "Forbidden", 403

    users = list(USERS.find({}, {"password": 0}))
    for u in users:
        u["_id"] = str(u["_id"])
        if "created_at" in u:
            u["created_at"] = u["created_at"].isoformat()
    return render_template("admin.html", users=users, current=user)

@app.route("/admin/delete/<user_id>", methods=["POST"])
@jwt_required(locations=["cookies"])
def admin_delete_user(user_id):
    user = json.loads(get_jwt_identity())
    if user["role"] != "Admin":
        return "Forbidden", 403
    if user_id == user["id"]:
        flash("Cannot delete your own account", "error")
        return redirect(url_for("admin_dashboard"))

    USERS.delete_one({"_id": ObjectId(user_id)})
    flash("User deleted", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/logout")
def logout():
    resp = redirect(url_for("login"))
    resp.delete_cookie("access_token_cookie")
    flash("Logged out successfully!", "success")
    return resp

if __name__ == "__main__":
    app.run(debug=True)
