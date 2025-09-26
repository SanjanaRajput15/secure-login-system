# secure-login-system
# Secure Login System (Flask + MongoDB)

## Overview
A secure login system built with Flask and MongoDB that supports user registration, login, JWT-based sessions, and role-based access control (Admin/User). Includes basic security features: password hashing (bcrypt), reCAPTCHA integration (optional), account lockout on repeated failed attempts.

## Features
- Registration with username, email, password, role (Admin/User)
- Password hashing with bcrypt
- Login and JWT token creation
- Admin dashboard to list and delete users (Admin role only)
- Account lockout after `5` failed attempts for `15` minutes
- Optional Google reCAPTCHA support

## Setup
1. Clone repo
2. Create virtualenv and install:
   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
