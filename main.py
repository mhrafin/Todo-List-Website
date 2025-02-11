import os
import secrets

from flask import Flask, flash, redirect, render_template, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import EmailField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email

# app setup
app = Flask(__name__)
# app configs
app.config["SECRET_KEY"] = secrets.token_hex(16)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"


# SQLAlchemy setup
class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
db.init_app(app)


## Models
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String, nullable=False)


with app.app_context():
    db.create_all()

# flask login manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Forms
class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    repeat_password = PasswordField("Repeat Password", validators=[DataRequired()])
    submit = SubmitField("Register")


@app.route("/")
def home():
    if current_user.is_authenticated:
        return render_template("home.html")
    
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print(form.data)
        email = form.data.get("email")
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user is None:
            flash("There is no account with this email!")
            return render_template("login.html", form=form)
        password = form.data.get("password")
        if not check_password_hash(pwhash=user.password, password=password):
            flash("Incorrect Password!")
            return render_template("login.html", form=form)

        login_user(user)
        return redirect("/")

    return render_template("login.html", form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        print(form.data)
        username = form.data.get("username")
        email = form.data.get("email")
        if db.session.execute(db.select(User).where(User.email == email)).scalar():
            flash("This email already is in use!")
            return render_template("register.html", form=form)
        pass1 = form.data.get("password")
        pass2 = form.data.get("repeat_password")
        if pass1 == pass2:
            new_user = User()
            new_user.username = username
            new_user.email = email
            new_user.password = generate_password_hash(
                password=pass1, method="pbkdf2:sha256:600000", salt_length=8
            )

            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            flash("login Successful!")
            return redirect("/")
        else:
            flash("Password didn't match!")
            return render_template("register.html", form=form)
    return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
