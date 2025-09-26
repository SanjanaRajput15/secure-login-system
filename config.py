import os
from dotenv import load_dotenv
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/secure_login")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change_this_for_prod")
SECRET_KEY = os.getenv("SECRET_KEY", "another_secret_for_csrf")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "")
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "")
