from flask import render_template,redirect,request,url_for,flash,session
from app import app
from models import db,User,Cart,Order,Advertise,Transaction,Category
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
from datetime import datetime

@app.route('/')
def home():
     return render_template("home.html")

    

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
    return redirect(url_for('creator_dashboard'))

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

    session['user_id'] = user.id
    flash("Login Sucessful!")
    return redirect(url_for('sponsor_dashboard'))

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

def admin_required(func):
    @wraps(func)
    def inner(*args,**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('creator_login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
             flash("You are not authorize to access this page!")
             return redirect(url_for('index'))
        return func (*args , **kwargs)
        
    return inner


@app.route('/index')
@auth_required
def index():
        user = User.query.get(session['user_id'])
        if user.is_admin:
             return redirect(url_for('admin'))
    
        return render_template('index.html')

@app.route('/creator_dashboard')
@auth_required
def creator_dashboard():
   
        user = User.query.get(session['user_id'])
        return render_template('creator_dashboard.html' , user=user)

@app.route('/creator_dashboard_profile')
@auth_required
def creator_dashboard_profile():
   
        user = User.query.get(session['user_id'])
        return render_template('creator_dashboard_profile.html' , user=user)
    
@app.route('/creator_dashboard_profile' ,methods = ['POST'])
@auth_required
def creator_dashboard_profile_post():
    username = request.form.get('username')
    cpassword = request.form.get('cpassword')
    password = request.form.get('password')
    name = request.form.get('name')

    if not username or not cpassword or not password:
        flash("Please out all the fields ")
        return redirect(url_for('creator_dashboard_profile'))
    
    user = User.query.get(session['user_id'])
    if not  check_password_hash(user.passhash,cpassword):
        flash("Incorrect Password")
        return redirect(url_for('creator_dashboard_profile'))

    if username != user.username:
        new_username = User.query.filter_by(username =username).first()
        if new_username:
            flash("Username already exists.!")
            return redirect(url_for('creator_dashboard_profile'))

    new_password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    user.username = username
    user.passhash = new_password_hash
    user.name = name
    db.session.commit()
    flash("Profile updated successfully!")
    return redirect(url_for('creator_dashboard_profile'))

@app.route('/sponsor_dashboard')
@auth_required
def sponsor_dashboard():
   
        user = User.query.get(session['user_id'])
        return render_template('sponsor_dashboard.html' , user=user)
    

@app.route('/sponsor_dashboard_profile')
@auth_required
def sponsor_dashboard_profile():
   
        user = User.query.get(session['user_id'])
        return render_template('sponsor_dashboard_profile.html' , user=user)
    
@app.route('/sponsor_dashboard_profile' ,methods = ['POST'])
@auth_required
def sponsor_dashboard_profile_post():
    username = request.form.get('username')
    cpassword = request.form.get('cpassword')
    password = request.form.get('password')
    name = request.form.get('name')

    if not username or not cpassword or not password:
        flash("Please out all the fields ")
        return redirect(url_for('sponsor_dashboard_profile'))
    
    user = User.query.get(session['user_id'])
    if not  check_password_hash(user.passhash,cpassword):
        flash("Incorrect Password")
        return redirect(url_for('sponsor_dashboard_profile'))

    if username != user.username:
        new_username = User.query.filter_by(username =username).first()
        if new_username:
            flash("Username already exists.!")
            return redirect(url_for('sponsor_dashboard_profile'))

    new_password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    user.username = username
    user.passhash = new_password_hash
    user.name = name
    db.session.commit()
    flash("Profile updated successfully!")
    return redirect(url_for('sponsor_dashboard'))


@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')
    return redirect(url_for('creator_login'))



#admin page

@app.route('/admin' )
@admin_required
def admin():
    categories = Category.query.all()

    return render_template('admin.html',categories = categories)


@app.route('/category/add')
@admin_required
def add_category():
     return render_template('category/add.html')

@app.route('/category/add' , methods = ['POST'])
@admin_required
def add_category_post():
     name = request.form.get('name')

     if not name:
          flash("Fill out all the fields!")
          return redirect(url_for('add_category'))
        
     category = Category(name=name)
     db.session.add(category)
     db.session.commit()
     flash("Category added successfully!")
     return redirect(url_for('admin'))

@app.route('/category/<int:id>')
@admin_required
def show_category(id):
     category = Category.query.get(id)
     if not category:
          flash("Category does not exist.")
          return redirect(url_for('admin'))
     return render_template('category/show.html' , category=category)

@app.route('/category/<int:id>/edit')
@admin_required
def edit_category(id):
     category = Category.query.get(id)
     if not category:
          flash("Category does not exists.")
          return redirect(url_for('admin'))
     return render_template('category/edit.html',category=category)

@app.route('/category/<int:id>/edit',methods = ['POST'])
@admin_required
def edit_category_post(id):
     category = Category.query.get(id)
     if not category:
          flash("Category does not exists.")
          return redirect(url_for('admin'))
     name = request.form.get('name')
     if not name:
          flash("Please fill out all the fields")
          return redirect(url_for('edit_category',id=id))
     category.name =name
     db.session.commit()
     flash("Category Updated successfully!")
     return redirect(url_for('admin'))


@app.route('/category/<int:id>/delete')
@admin_required
def delete_category(id):
     category = Category.query.get(id)
     if not category:
          flash("Category does not exist.")
          return redirect(url_for('admin'))

     return render_template("category/delete.html" , category = category)

@app.route('/category/<int:id>/delete' , methods = ['POST'])
@admin_required
def delete_category_post(id):
     category = Category.query.get(id)
     if not category:
          flash("Category does not exist.")
          return redirect(url_for('admin'))
     db.session.delete(category)
     db.session.commit()

     flash("Category deleted sucessfully.")
     return redirect(url_for("admin"))

@app.route('/advertise/add/<int:category_id>')
@admin_required
def add_advertise(category_id):
    categories = Category.query.all()
    category = Category.query.get(category_id)
    if not category:
        flash("Category does not exist.")
        return redirect(url_for('admin'))
    now = datetime.now().strftime('%Y-%m-%d')
    return render_template('advertise/add.html' , category=category , categories = categories,now=now)

@app.route('/advertise/add/' , methods = ['POST'])
@admin_required
def add_advertise_post():
    name = request.form.get('name')
    price = request.form.get('price')
    category_id = request.form.get('category_id')
    quantity = request.form.get('quantity')
    description = request.form.get('description')
    date = request.form.get('date')

    category = Category.query.get(category_id)
    if not category:
        flash("Category does not exists.")
        return redirect(url_for('admin'))

    if not name or not price or not quantity or not date or not description:
        flash("Please fill all the fields")
        return redirect(url_for('add_advertise',category_id=category_id))
    try:
        quantity = int(quantity)
        price = float(price)
        date = datetime.strptime(date,'%Y-%m-%d')
    except ValueError:
        flash("Invalid quantity or price")
        return redirect(url_for('add_advertise',category_id=category_id))
    if price <=0 or quantity <=0:
        flash("Invalid quantity or Price")
        return redirect(url_for('add_advertise',category_id=category_id))
    if date<datetime.now():
        flash("Invalid Relase date.")
        return redirect(url_for('add_advertise',category_id=category_id))
    
    advertise = Advertise(name=name,price = price,category=category,quantity = quantity,description=description,date=date)
    db.session.add(advertise)
    db.session.commit()
    flash ("Advertise added sucessfully!")
    return redirect(url_for('show_category', id=category_id))
         
@app.route('/advertise/<int:id>/edit')
@admin_required
def edit_advertise(id):
    categories = Category.query.all()
    advertise = Advertise.query.get(id)
    
    return render_template('advertise/edit.html' ,categories=categories,advertise=advertise)

@app.route('/advertise/<int:id>/edit',methods=['POST'])
@admin_required
def edit_advertise_post(id):
    name = request.form.get('name')
    price = request.form.get('price')
    category_id = request.form.get('category_id')
    quantity = request.form.get('quantity')
    description = request.form.get('description')
    date = request.form.get('date')

    category = Category.query.get(category_id)
    if not category:
        flash("Category does not exists.")
        return redirect(url_for('admin'))

    if not name or not price or not quantity or not date or not description:
        flash("Please fill all the fields")
        return redirect(url_for('add_advertise',category_id=category_id))
    try:
        quantity = int(quantity)
        price = float(price)
        date = datetime.strptime(date,'%Y-%m-%d')
    except ValueError:
        flash("Invalid quantity or price")
        return redirect(url_for('add_advertise',category_id=category_id))
    if price <=0 or quantity <=0:
        flash("Invalid quantity or Price")
        return redirect(url_for('add_advertise',category_id=category_id))
    if date<datetime.now():
        flash("Invalid Relase date.")
        return redirect(url_for('add_advertise',category_id=category_id))
    
    advertise = Advertise.query.get(id)
    advertise.name=name
    advertise.price=price
    advertise.category=category
    advertise.quantity=quantity
    advertise.date=date
    db.session.commit()
    flash ("Advertise edited sucessfully!")
    return redirect(url_for('show_category', id=category_id))

@app.route('/advertise/<int:id>/delete')
@admin_required
def delete_advertise(id):
    advertise = Advertise.query.get(id)
    if not advertise:
        flash("Advertise doest not exists ")
        return redirect(url_for('admin'))

    return render_template('advertise/delete.html',advertise=advertise)

@app.route('/advertise/<int:id>/delete',methods=["POST"])
@admin_required
def delete_advertise_post(id):
    advertise = Advertise.query.get(id)
    if not advertise:
        flash("Advertise doest not exists")
        return redirect(url_for('admin'))
    category_id=advertise.category.id
    db.session.delete(advertise)
    db.session.commit()

    flash("Advertise deleted sucessfuly")
    return redirect(url_for('show_category', category_id=category_id))
         
     