"""
So far the main problem is about modifying a user.
The previous password being saved as hashed cannot be saved again.
"""

from flask import Flask, flash, render_template, redirect, url_for
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
    return User.query.get(user_id)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    # Relationships
    roles = db.relationship('Role', secondary='user_roles')

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)
    
    def __repr__(self):
        return 'User {user}'.format(user=self.username, passw=self.password)

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "{role}".format(role=self.name)

class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

class ViewsMixin:
    """
    Class to include in each Admin Views
    """
    def is_accessible(self):
        """
        Gives access to the view if user has admin access.
        """
        if current_user.is_authenticated:
            """
            curent_user.is_authenticated prevent a non authenticated to crash the app.
            This will send the user to self.inaccessible_callback()
            """
            if 'Admin' in [str(roles) for roles in current_user.roles]:
                return True
                
    def inaccessible_callback(self, name, **kwargs):
        """
        Redirect user without admin access to admin_unaccessible view.
        """
        return redirect(url_for("admin_unaccessible"))

class UserView(ViewsMixin, ModelView):
    """
    Tab view for the user database.
    Note : I need to modify the update_model method to keep password as hashed and not as a string.
    """
    def on_model_change(self, form, User, is_created=False):
        """
        Changes the submitted password as a hashed password.
        """
        User.password = generate_password_hash(form.password.data, method="sha256")

class RoleView(ViewsMixin, ModelView):
    """
    Tab view for the roles database
    """
    pass

class HomeAdminView(ViewsMixin, AdminIndexView):
    """
    Tab view for the admin home page
    """
    pass

class LoginForm(FlaskForm):
    username = StringField("username", validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField("remember me")

admin = Admin(app, index_view=HomeAdminView())
admin.add_view(UserView(User, db.session))
admin.add_view(RoleView(Role, db.session))

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # first() since all username are supposed to be unique
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template("good.html", form=form)
    return render_template("index.html", form=form)

@app.route("/logout")
def logout():
    logout_user()
    return "logged out"

@app.route("/myapp")
def myapp():
    return redirect("good.html")

@app.route("/admin_unaccessible")
def admin_unaccessible():
    return "Sorry you don't have the right access to the administration page."

if __name__ == "__main__":
    app.run(debug=True)