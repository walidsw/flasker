from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.file import FileAllowed, FileField
import os
from werkzeug.utils import secure_filename

#1234n - for nayan@gmail.com

app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://root:walidswadhin@localhost/users"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:root@127.0.0.1:8889/users"

app.config['SECRET_KEY'] = "This is super Duper Key, walk!"

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'profile_pics')

db = SQLAlchemy(app)



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # where to redirect if not logged in



class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"User {self.name} has been created at {self.date_added}"
    
class BlogTable(db.Model):
    blog_id = db.Column(db.Integer, primary_key=True)
    blog_title = db.Column(db.String(1000), nullable=False)
    blog_content = db.Column(db.String(5000), nullable=False)
    date_added = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # Foreign key relationship to Users table
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"Blog '{self.blog_title[:30]}...' by User ID {self.user_id}"

class Comment(db.Model):
    comment_id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    date_posted = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Foreign keys
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_table.blog_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f"Comment by User ID {self.user_id} on Blog ID {self.blog_id}"

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    profile_pic = db.Column(db.String(300), default='default.jpg')


# create tables
with app.app_context():
    db.create_all()


class ProfileForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    profile_pic = FileField("Update Profile Picture", validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')
    ])
    submit = SubmitField("Update Profile")






class CommentForm(FlaskForm):
    content = TextAreaField("Leave a Comment", validators=[DataRequired()])
    submit = SubmitField("Post Comment")



class BlogForm(FlaskForm):
    title = StringField("Blog Title", validators=[DataRequired()])
    content = TextAreaField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Post Blog")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class UserForm(FlaskForm):
    name = StringField("Name ", validators=[DataRequired()])
    email = StringField("Email ", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("SUBMIT")



class NamerForm(FlaskForm):
    name = StringField("What's Your Name? ", validators=[DataRequired()])
    submit = SubmitField("SUBMIT")





@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/signup', methods=['GET','POST'])
def signup():
    email = None 
    form = UserForm()
    flag = 0
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first() 
        if user is None:
            hashed_password = generate_password_hash(form.password.data)
            user = Users(name=form.name.data, email=form.email.data,password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flag = 1
            email = form.email.data
        form.name.data=''
        form.email.data=''

    if(flag):
        flash("User Added Successfully")
    else:
        flash("Sorry Try Again")
    
    return render_template(
        "signup.html", 
        form=form,
        flag=flag,
        email=email
    )

@app.route('/user/user_post', methods=['GET', 'POST'])
def user_post():
    flag = 0
    form = BlogForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        blog = BlogTable(
            blog_title=title,
            blog_content=content,
            user_id=current_user.id
        )
        db.session.add(blog)
        db.session.commit()
        form.title.data = ''
        form.content.data = ''
        flag = 1
        flash("Blog post submitted successfully!")
    return render_template("user_post.html", form=form, flag=flag)


@app.route('/')
def index():
    return render_template("index.html")




@app.route('/user/blog', methods=['GET', 'POST'])
def blog():
    form = CommentForm()
    blogs = db.session.query(BlogTable, Users).join(Users, BlogTable.user_id == Users.id).order_by(BlogTable.date_added.desc()).all()
    
    # Load all comments for all blogs (optional optimization: load on demand)
    all_comments = db.session.query(Comment, Users).join(Users, Comment.user_id == Users.id).all()
    
    if form.validate_on_submit() and current_user.is_authenticated:
        comment = Comment(
            content=form.content.data,
            blog_id=int(request.form['blog_id']),
            user_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('blog'))  # to refresh
    
    return render_template("blog.html", blogs=blogs, form=form, all_comments=all_comments)



@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500

@app.route('/name', methods=['GET','POST'])
def name():
    name = None
    form = NamerForm()

    if form.validate_on_submit():
        name = form.name.data 
        form.name.data = ''
        flash("Form Submitted Successfully!")
    return render_template("name.html", name=name, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    flag = 0
    form = LoginForm()
    if form.validate_on_submit():
        # Find user by email
        user = Users.query.filter_by(email=form.email.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Logged In Successfully.")
            flag = 1
            return render_template("index.html")
        else:
            form.email.data = ''
            flash("Login Failed.")
    return render_template("login.html", form=form, flag=flag)


@app.route('/logout')

def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return render_template("index.html")

@app.route('/delete_blog/<int:blog_id>', methods=['POST'])
@login_required
def delete_blog(blog_id):
    blog = BlogTable.query.get_or_404(blog_id)

    if blog.user_id != current_user.id:
        flash("You are not authorized to delete this blog.", "danger")
        return redirect(url_for('blog'))

    Comment.query.filter_by(blog_id=blog.blog_id).delete()
    db.session.delete(blog)
    db.session.commit()
    flash("Blog post deleted successfully.", "success")
    return redirect(url_for('blog'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()

    if not user_profile:
        user_profile = UserProfile(user_id=current_user.id)
        db.session.add(user_profile)
        db.session.commit()

    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.email = form.email.data

        file = request.files['profile_pic']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user_profile.profile_pic = filename

        db.session.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for('profile'))

    form.name.data = current_user.name
    form.email.data = current_user.email

    return render_template("profile.html", form=form, user=current_user, profile=user_profile)

