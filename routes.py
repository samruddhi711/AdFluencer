from flask import render_template,redirect,request,url_for,flash
from app import app
from models import db,User,Cart,Order,Advertise,Transaction
from werkzeug.security import generate_password_hash,check_password_hash

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/creator_login')
def creator_login():
    return render_template('creator_login.html')

@app.route('/creator_login' , methods = ['POST'])
def creator_login_post():
    username =request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Please fill out all the fields.")
        return redirect(url_for('creator_login'))
    
    user = User.query.filter_by(username=username).first()

    if not user:
        flash("Username does not exists .")
        return redirect(url_for('creator_login'))
    if not check_password_hash(user.passhash ,password):
        flash("Incorrect Password")
        return redirect(url_for('creator_login'))

    return redirect(url_for('index'))

@app.route('/sponsor_login')
def sponsor_login():
    return render_template('sponsor_login.html')

@app.route('/sponsor_login' , methods = ['POST'])
def sponsor_login_post():
    username =request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Please fill out all the fields.")
        return redirect(url_for('sponsor_login'))
    
    user = User.query.filter_by(username=username).first()

    if not user:
        flash("Username does not exists .")
        return redirect(url_for('sponsor_login'))
    if not check_password_hash(user.passhash ,password):
        flash("Incorrect Password")
        return redirect(url_for('sponsor_login'))

    return redirect(url_for('index'))



@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods = ['POST','GET'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    name = request.form.get('name')
    
    if not username or not password or not confirm_password:
        flash ("Please fill out all the fields . ")
        return redirect (url_for("register"))
    
    if password != confirm_password:
        flash("Password do not Match .!")
        return redirect (url_for("register"))

    user = User.query.filter_by(username = username).first()

    if user:
        flash("Username already exists!")
        return redirect (url_for("register"))
    
    password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    new_user = User(username=username,passhash = password_hash,name = name)
    db.session.add(new_user)
    db.session.commit()
    return redirect (url_for("index"))