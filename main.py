from flask import Flask, render_template, g
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = "supersecretkey"
Bootstrap(app)
db = SQLAlchemy(app)
login = LoginManager(app)

@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    is_admin = db.Column(db.Boolean())

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password, method="sha256")
    
    def __repr__(self):
        return '<User {user} and password {passw}>'.format(user=self.username, passw=self.password)

class UserView(ModelView):
    def is_accessible(self):
        #user_id = current_user._
        #print("This is the user_id", user_id)
        return True
        #return current_user.
    
    def on_model_change(self, form, User, is_created=False):
        """
        While being in the 
        """
        User.password = generate_password_hash(form.password.data, method="sha256")

class HomeAdminView(AdminIndexView):
    def is_accessible(self):
        return True

class LoginForm(FlaskForm):
    username = StringField("username", validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField("remember me")

admin = Admin(app, index_view=HomeAdminView())
admin.add_view(UserView(User, db.session))

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # first() since all username are supposed to be unique
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                return render_template("good.html", form=form)
    return render_template("index.html", form=form)

@app.route("/logout")
def logout():
    logout_user()
    return "logged out"

if __name__ == "__main__":
    app.run(debug=True)