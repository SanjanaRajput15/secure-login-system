# secure-login-system
# Secure Login System (Flask + MongoDB)

## Project Overview
A secure login system built with Flask and MongoDB that supports user registration, login, JWT-based sessions, and role-based access control (Admin/User). Includes basic security features: password hashing (bcrypt), reCAPTCHA integration (optional), account lockout on repeated failed attempts.

## Features

User Registration: Register with username, email, password, and role (User/Admin).
Password Security: Passwords are hashed using Bcrypt.
Login: Authenticate users using email and password.
JWT Sessions: Secure login sessions stored in HTTP-only cookies.
Role-Based Dashboards:
Users see a simple dashboard.
Admins can view and manage all users.
Admin Actions: Delete other users (cannot delete self).
Validation & Security:
Password strength validation (letters, numbers, special characters)
Optional reCAPTCHA
Flash messages for feedback

## Tech Stack

Backend: Python, Flask, Flask-PyMongo, Flask-Bcrypt, Flask-JWT-Extended
Database: MongoDB
Frontend: HTML, CSS,  templates
Security: JWT, Bcrypt, Input validation, reCAPTCHA


## Setup Instructions

## Clone Repository

git clone https://github.com/SanjanaRajput15/secure-login-system.git
cd secure-login-system

## Create Virtual Environment & Install Dependencies

python -m venv venv
source venv/bin/activate       # Linux/Mac
venv\Scripts\activate          # Windows
pip install -r requirements.txt

## Run the Application
python app.py


## Access in Browser

http://127.0.0.1:5000
