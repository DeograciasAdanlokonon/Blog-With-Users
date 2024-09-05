from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os


# TODO: admin decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
# app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# Initialize Gravatar
gravatar = Gravatar(app=app)

# TODO: Configure Flask-Login


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# Flask Login manager
login_manager = LoginManager()
login_manager.init_app(app)


# user loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONFIGURE TABLES

# TODO: Create a User table for all your registered users. PARENT TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):  # TODO: CHILD TABLE
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # One-to-Many relation between User and BlogPost
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    # relation between Blogpost and Comment
    comments = relationship("Comment", back_populates="post")


# TODO: Create a Comment table for all comment. CHILD TABLE
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    comment: Mapped[str] = mapped_column(Text, nullable=False)

    # One-to-Many relation between User and Comment
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")

    # One-to-Many relation between BlogPost and Comment
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    # initialize registration form
    register_form = RegisterForm()

    try:
        # on submit
        if register_form.validate_on_submit():
            name = register_form.name.data
            email = register_form.email.data

            # if passwords are equal
            if register_form.password.data == register_form.confirm_password.data:
                password = generate_password_hash(register_form.password.data, salt_length=8)

                # check if user  already exist
                result = db.session.execute(db.select(User).where(User.email == email))
                user = result.scalar()

                if not user:
                    # create new user
                    new_user = User(
                        name=name,
                        email=email,
                        password=password
                    )

                    # insert new user in db
                    db.session.add(new_user)
                    db.session.commit()

                    login_user(new_user)

                    # head user to login page
                    return redirect(url_for('get_all_posts', current_user=current_user))
                else:
                    flash('You already have an account with that email. Please, sign in!')
                    return redirect(url_for('login'))
            else:
                flash('Your passwords should be equal.')
    except Exception as e:
        print(str(e))

    return render_template("register.html", form=register_form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    # initialize login form
    login_form = LoginForm()

    try:
        # if form submitted
        if login_form.validate_on_submit():
            email = login_form.email.data
            password = login_form.password.data

            # check if user exists in db
            result = db.session.execute(db.select(User).where(User.email == email))
            user = result.scalar()

            if user:
                # check if password is correct
                if check_password_hash(user.password, password=password):
                    # let user log in
                    login_user(user)

                    flash('Logged in Successfully!')
                    return redirect(url_for('get_all_posts', current_user=current_user))
                else:
                    flash('Password incorrect! Please, try again.')
            else:
                flash('The email address does not exist. Please, try again!')
    except Exception as e:
        print(str(e))

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    # get comment form
    comment_form = CommentForm()

    # get post from post_id
    requested_post = db.get_or_404(BlogPost, post_id)

    try:
        if comment_form.validate_on_submit():
            if current_user.is_authenticated:
                comment = comment_form.comment.data

                new_comment = Comment(
                    comment=comment,
                    post_id=post_id,
                    author_id=current_user.id
                )

                # insert new comment in db
                db.session.add(new_comment)
                db.session.commit()

                flash('Comment successfully posted!')
            else:
                flash('You need to log in or register to comment a post.')
                return redirect(url_for('login'))
    except Exception as e:
        print(str(e))

    # fetch all comments of this post into a list of comments
    result = db.session.execute(db.select(Comment))
    comments = result.scalars().all()  # return a list of comments

    return render_template("post.html", post=requested_post, form=comment_form, comments=comments)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
