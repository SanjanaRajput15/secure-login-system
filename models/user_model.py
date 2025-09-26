from datetime import datetime
from flask_bcrypt import generate_password_hash

def make_user_doc(username, email, password, role="User"):
    return {
        "username": username,
        "email": email,
        "password": generate_password_hash(password).decode("utf-8"),
        "role": role,
        "created_at": datetime.utcnow(),
        "failed_attempts": 0,
        "lock_until": None
    }
