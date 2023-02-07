from flask import Flask, render_template, redirect, url_for, flash,request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,RegisterUser,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_gravatar import Gravatar
Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog_rm.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):

    return User.query.get(int(id))



##CONFIGURE TABLES

class BlogPost(db.Model,Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User",lazy='subquery', back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")



class User(UserMixin, db.Model,Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comment=relationship("Comment", back_populates="comment_user")

class Comment(db.Model,Base):
    __tablename__ = "comments"
    comment_id=db.Column(db.Integer, primary_key=True)
    comment_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_user=relationship("User", back_populates="comment")
    post_id=db.Column(db.Integer,db.ForeignKey('blog_posts.id'))
    parent_post=relationship("BlogPost", back_populates="comments")
    comment_text = db.Column(db.Text)
# db.create_all()



def admin_only(func):
    @wraps(func)
    def wrapper( *args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id==1:
                return func(*args, **kwargs)
            else:
                return f"Error 403 forbidden /n You dont have permission to see this route"
        else:
            return f"Error 403 forbidden /n You dont have permission to see this route"

    return wrapper


# Create all the tables in the database
# db.create_all()



@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,current_user=current_user)


@app.route('/register',methods=["GET","POST"])
def register():
    form=RegisterUser()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('email already registered,please try login')
            return redirect(url_for('login'))

        email = form.email.data
        password1 = form.password.data
        name = form.name.data
        password2 = generate_password_hash(password1, method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=email,
                            password=password2,
                            name=name,
                            )

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts",id=new_user.id))
    return render_template("register.html",form=form,current_user=current_user)


@app.route('/login',methods=["GET","POST"])
def login():
    form=LoginForm()
    if request.method == 'POST':
        email=form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('email-id doesnt exist,please register first')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('incorrect password,please try again')
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('get_all_posts',id=user.id))

    return render_template("login.html",form=form,current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form=CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for('login'))
        new_comment=Comment(comment_text=form.body.data,
                            comment_user=current_user,
                            parent_post=requested_post
                            )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post,current_user=current_user,form=form)


@app.route("/about")
def about():
    return render_template("about.html",current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html",current_user=current_user)


@app.route("/new-post",methods=["GET","POST"])
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
    return render_template("make-post.html", form=form,current_user=current_user)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
