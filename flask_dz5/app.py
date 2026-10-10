from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
from functools import wraps
import secrets

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-me-secret-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'notes.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=1)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class Notes(db.Model):
    __tablename__ = "notes"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    text = db.Column(db.Text, nullable=False)
    subtitle = db.Column(db.String(200), nullable=True)


class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    token = db.Column(db.String(100), nullable=True)
    token_expires = db.Column(db.DateTime, nullable=True)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            flash("Войдите в систему", "error")
            return redirect(url_for("login"))

        user = Users.query.get(user_id)
        if not user or not user.token or user.token_expires < datetime.utcnow():
            session.clear()
            flash("Сессия истекла. Войдите снова.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            flash("Заполните все поля", "error")
            return render_template("register.html")

        if Users.query.filter_by(username=username).first():
            flash("Логин уже занят", "error")
            return render_template("register.html")

        if Users.query.filter_by(email=email).first():
            flash("Email уже зарегистрирован", "error")
            return render_template("register.html")

        user = Users(
            username=username,
            email=email,
            password=generate_password_hash(password),
        )
        db.session.add(user)
        db.session.commit()

        flash("Регистрация успешна! Войдите.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        user = Users.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Генерация токена (К4)
            user.token = secrets.token_hex(32)
            user.token_expires = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()

            session.permanent = True
            session["user_id"] = user.id
            return redirect(url_for("index"))

        flash("Неверный логин или пароль", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        user = Users.query.get(user_id)
        if user:
            user.token = None
            user.token_expires = None
            db.session.commit()
    session.clear()
    flash("Вы вышли из системы", "success")
    return redirect(url_for("home"))


@app.route("/notes", methods=["GET", "POST"])
@login_required
def notes_page():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        text = request.form.get("text", "").strip()
        subtitle = request.form.get("subtitle", "").strip() or None

        if title and text:
            note = Notes(title=title, text=text, subtitle=subtitle)
            db.session.add(note)
            db.session.commit()

        return redirect(url_for("notes_page"))

    all_notes = Notes.query.order_by(Notes.id.desc()).all()
    return render_template("notes.html", notes=all_notes)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)