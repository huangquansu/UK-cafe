from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from functools import wraps
from flask_gravatar import Gravatar
import os


# app = Flask(__name__)
# uri = os.getenv("DATABASE_URL", 'sqlite:///cafes.db')
# if uri.startswith("postgres://"):
#     uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


class Join(FlaskForm):
    name = StringField('Your name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField("Join US")


class Login(FlaskForm):
    email = EmailField('Account', validators=[DataRequired()], render_kw={'placeholder': 'Email'})
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("LET ME IN")


class CafeComment(FlaskForm):
    body = CKEditorField('Comment', validators=[DataRequired()])
    submit = SubmitField('SUBMIT COMMENT')


class NewShop(FlaskForm):
    shop_name = StringField('Shop name', validators=[DataRequired()])
    map_url = StringField('address_url', validators=[DataRequired()])
    shop_img = StringField('Photo_url', validators=[DataRequired()])
    location = StringField('City', validators=[DataRequired()])
    socket = StringField('socket', validators=[DataRequired()], render_kw={'placeholder': '1 or 0'})
    toilet = StringField('toilet', validators=[DataRequired()], render_kw={'placeholder': '1 or 0'})
    wifi = StringField('wifi', validators=[DataRequired()], render_kw={'placeholder': '1 or 0'})
    call = StringField('call', validators=[DataRequired()], render_kw={'placeholder': '1 or 0'})
    seat = StringField('seats', validators=[DataRequired()], render_kw={'placeholder': '10~20+'})
    price = StringField('coffee_price', validators=[DataRequired()], render_kw={'placeholder': 'EU coin'})
    submit = SubmitField("Suggest place")


class Account(db.Model, UserMixin):
    __tablename__ = 'account'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment', back_populates='comment_author')

    def __repr__(self):
        return f'name'
    

class Cafe(db.Model):
    __tablename__ = 'cafe'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    map_url = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    has_sockets = db.Column(db.String(250), nullable=False)
    has_toilet = db.Column(db.String(250), nullable=False)
    has_wifi = db.Column(db.String(250), nullable=False)
    can_take_calls = db.Column(db.String(250), nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    coffee_price = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment', back_populates='parent_post')

    def __repr__(self):
        return f'Shop {self.name}'


class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('account.id'))
    comment_author = relationship('Account', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('cafe.id'))
    parent_post = relationship('Cafe', back_populates='comments')
    text = db.Column(db.String(250), nullable=False)


db.create_all()


def admin_only(function):
    @wraps(function)
    def decorate_function(*args, **kwargs):
        if current_user.get_id() != '1':
            return abort(403)
        return function(*args, **kwargs)
    return decorate_function


@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(user_id)


@app.route('/')
def home():
    return render_template('index.html', logged_in=current_user.is_authenticated)


@app.route('/search', methods=['GET', 'POST'])
def search():
    socket_query = Cafe.query.filter_by(has_sockets=1)
    toilet_query = Cafe.query.filter_by(has_toilet=1)
    wifi_query = Cafe.query.filter_by(has_wifi=1)
    call_query = Cafe.query.filter_by(can_take_calls=1)
    return render_template('city.html', socket_query=socket_query, toilet_query=toilet_query, wifi_query=wifi_query,
                           call_query=call_query)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Join()
    if form.validate_on_submit():
        if Account.query.filter_by(email=form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            new_user = Account(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(password=form.password.data, method='pbkdf2:sha1', salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template('register.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        user = Account.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(password=form.password.data, pwhash=user.password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Password incorrect, Please try again.')
                redirect(url_for('login'))
        else:
            flash('That email does not exist,please try again')
            return redirect(url_for('login'))
    return render_template('login.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/shop/<int:shop_id>', methods=['GET', 'POST'])
def show_shop(shop_id):
    request_shop = Cafe.query.get(shop_id)
    form = CafeComment()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for('login'))
        new_comment = Comment(
            text=form.body.data,
            comment_author=current_user,
            parent_post=request_shop
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_shop', shop_id=request_shop.id))
    comment = Comment.query.filter_by(post_id=shop_id)
    shop_rename = request_shop.name.replace(' ', '%20')
    shop_src = f"https://maps.google.com/maps?q={shop_rename}&t=&z=13&ie=UTF8&iwloc=&output=embed"
    return render_template('shop.html', form=form, logged_in=current_user.is_authenticated, shop=request_shop,
                           comments=comment, shop_src=shop_src)


@app.route("/new-shop", methods=['GET', 'POST'])
def add_new_shop():
    form = NewShop()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for('login'))
        if current_user.get_id() != 1:
            flash('Your account are not authenticated.')
            return redirect(url_for('add_new_shop'))
        new_shop = Cafe(
            name=form.shop_name.data,
            map_url=form.map_url.data,
            img_url=form.shop_img.data,
            location=form.location.data,
            has_sockets=form.socket.data,
            has_wifi=form.wifi.data,
            can_take_calls=form.call.data,
            seats=form.seat.data,
            coffee_price=form.price.data
        )
        db.session.add(new_shop)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("make_shop.html", form=form, logged_in=current_user.is_authenticated)


if __name__ == '__main__':
    app.run(debug=True)
