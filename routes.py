from flask import render_template,redirect,request,url_for,flash,session
from app import app
from models import db,User,Cart,Order,Advertise,Transaction
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps



    

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

    session['user_id'] = user.id
    flash("Login Sucessful!")
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

@app.route('/admin' )
def admin():
    return render_template('admin.html')


#--------
#decorator for auth required
def auth_required(func):
    @wraps(func)
    def inner(*args,**kwargs):
        if 'user_id' in session:
            return func (*args , **kwargs)
        else:
            flash("Please login to continue")
            return redirect(url_for('creator_login'))
    return inner

@app.route('/')
@auth_required
def index():
    
        return render_template('index.html')

@app.route('/creator_dashboard')
@auth_required
def creator_dashboard():
   
        user = User.query.get(session['user_id'])
        return render_template('creator_dashboard.html' , user=user)
    
@app.route('/creator_dashboard' ,methods = ['POST'])
@auth_required
def creator_dashboard_post():
    username = request.form.get('username')
    cpassword = request.form.get('cpassword')
    password = request.form.get('password')
    name = request.form.get('name')

    if not username or not cpassword or not password:
        flash("Please out all the fields ")
        return redirect(url_for('creator_dashboard'))
    
    user = User.query.get(session['user_id'])
    if not  check_password_hash(user.passhash,cpassword):
        flash("Incorrect Password")
        return redirect(url_for('creator_dashboard'))

    if username != user.username:
        new_username = User.query.filter_by(username =username).first()
        if new_username:
            flash("Username already exists.!")
            return redirect(url_for('creator_dashboard'))

    new_password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    user.username = username
    user.passhash = new_password_hash
    user.name = name
    db.session.commit()
    flash("Profile updated successfully!")
    return redirect(url_for('creator_dashboard'))

@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')
    return redirect(url_for('creator_login'))
