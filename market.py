# flask package
from flask import Flask,render_template,request
from flask import redirect
from flask import url_for
# sql handling module
from flask_sqlalchemy import SQLAlchemy
# forms module of flask
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms import PasswordField
from wtforms import SubmitField 
from wtforms.validators import Length
from wtforms.validators import EqualTo
from wtforms.validators import Email
from wtforms.validators import ValidationError
from wtforms.validators import DataRequired  # for the fields you need to be filled mandatory
# for displaying the messages in front-end
from flask import flash , get_flashed_messages
# for login management
from flask_login import LoginManager
# library for crypting the password 
from flask_bcrypt import Bcrypt
# login user
from flask_login import login_user
from flask_login import UserMixin
from flask_login import logout_user
from flask_login import login_required
from flask_login import current_user
# application configuration
app = Flask(__name__)

# configuration of database file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
# act as a security layer to form 
app.config['SECRET_KEY'] = 'malhotra2003'
# database configuration
db = SQLAlchemy(app)
# configuuring the cryption 
bcrypt = Bcrypt(app) # for applying the encryption on our database in app
# login manager
login_manager = LoginManager(app)
login_manager.login_view = "login_page"



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(length=30),unique=True,nullable=False)
    email_address = db.Column(db.String(length=50),nullable=False,unique=True)
    password_hash = db.Column(db.String(length=60),nullable=False)
    budget = db.Column(db.Integer(),nullable=False,default=1000) # setting default value 1000 as the initial budget to customer
    items = db.relationship('Item', backref='owned_user',lazy = True) # here lazy = true is used in order to fetch all the related data 
    def __repr__(self):
        return f'username {self.username} , password {self.password_hash}'
    
    @property
    def prettier_budget(self):
            return f"$ {self.budget}"
    
    @property
    def password(self):
        return self.password
    
    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password) # encrypting the password 

    def check_password_correction(self,attempted_password):
        return bcrypt.check_password_hash(self.password_hash,attempted_password)
    
    def can_purchase(self,item_obj):
        return self.budget >= item_obj.price        
        
    def can_sell(self, item_obj):
        return item_obj in self.items        
               
# Table Item
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True) # combination of non-null as well as unique 
    name = db.Column(db.String(length=20),nullable = False,unique = True) # setting the string type column
    price = db.Column(db.Integer(),nullable = False) 
    barcode = db.Column(db.String(length=12),nullable = False,unique = True)
    description = db.Column(db.String(length=1024)) # this can be null if you dont want to add description
    owner = db.Column(db.Integer(),db.ForeignKey(User.id))
    def __repr__(self):
        return f'Item{self.name}'
    
    def buy(self,user): # ownership guving function 
        self.owner = user.id  # Assigning the user name to the product as now it going to be owned by the logged in user after purchasing         
        user.budget -= self.price
        db.session.commit()
    
    def sell(self,user):
        self.owner = None
        user.budget += self.price
        db.session.commit()
    
# registration form field : kind of class
class RegisterForm(FlaskForm):
    
    # user name validation function 
    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first() # searching that the user you are going to register already exists or not
        if user:
            raise ValidationError('Username already exists!')  
    
    def validate_email(self, email_to_check):
        user = User.query.filter_by(email_address=email_to_check.data).first() # searching that the user you are going to register already exists or not
        if user:
            raise ValidationError('Account through this email already exists!')  
      
    username = StringField(label='Username',validators=[Length(min=2,max=20),DataRequired()]) # validation that the username should be between 2 and 20 characters
    email_address = StringField(label='Email-address',validators=[Email(),DataRequired()])
    password1 = PasswordField(label = "Password",validators=[Length(min=8),DataRequired()])
    password2 = PasswordField(label = "Confirm Password",validators=[EqualTo('password1'),DataRequired()])
    submit = SubmitField(label='Create account')
#    password1 = StringField(label=' Enter your password')
#    password2 = StringField(label=' Re-Enter your password')
#    not using this string field as password field as flask form provides different field for password    



# login form
class LoginForm(FlaskForm):
    username = StringField(label='User Name:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign in')
  
#  purchasing form
class PurchaseItemForm(FlaskForm):
    submit = SubmitField(label='Purchase Item')  
    
class SellItemForm(FlaskForm):
    submit = SubmitField(label='Sell Item!')

    
    
# Routes         
#rendering templates
@app.route('/') # initial page of the site
@app.route('/home') # another app route to the website
def home():
    return render_template('home.html')

#@app.route('/') # decorators
#def hello_world():
#    return "Hello World!"

@app.route('/about/<username>') # decorators
def about_page(username): # using name in the page as displaying it using f-string
    return f"This is page about ....{username}"


@app.route('/market', methods=['GET', 'POST'])
@login_required
def market_page():
    purchase_form = PurchaseItemForm()
    selling_form = SellItemForm()
    if request.method == "POST":
        #Purchase Item Logic
        purchased_item = request.form.get('purchased_item')
        p_item_object = Item.query.filter_by(name=purchased_item).first()
        if p_item_object:
            if current_user.can_purchase(p_item_object):
                p_item_object.buy(current_user)
                flash(f"Congratulations! You purchased {p_item_object.name} for {p_item_object.price}$", category='success')
            else:
                flash(f"Unfortunately, you don't have enough money to purchase {p_item_object.name}!", category='danger')
        #Sell Item Logic
        sold_item = request.form.get('sold_item')
        s_item_object = Item.query.filter_by(name=sold_item).first()
        if s_item_object:
            if current_user.can_sell(s_item_object):
                s_item_object.sell(current_user)
                flash(f"Congratulations! You sold {s_item_object.name} back to market!", category='success')
            else:
                flash(f"Something went wrong with selling {s_item_object.name}", category='danger')


        return redirect(url_for('market_page'))

    if request.method == "GET":
        items = Item.query.filter_by(owner=None)
        owned_items = Item.query.filter_by(owner=current_user.id)
        return render_template('market.html', items=items, purchase_form=purchase_form, owned_items=owned_items, selling_form=selling_form)
    
    
 
# register page 
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data,
                              email_address=form.email_address.data,
                              password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        return redirect(url_for('market_page'))
    if form.errors != {}: #If there are not errors from the validations
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')

    return render_template('register.html', form=form)

# login page routing
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(
                attempted_password=form.password.data
        ):
            login_user(attempted_user)
            flash(f'Success! You are logged in as: {attempted_user.username}', category='success')
            return redirect(url_for('market_page'))
        else:
            flash('Username and password are not match! Please try again', category='danger')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out!!",category='info')    
    return render_template('home.html')

# main function
if __name__ == "__main__":
    app.run(debug=True)




# user created intially is having 
# username : Manav Malhotra
# password : malhotra2003
# email : mmalhotra_be21@thapar.edu

# username : jasleen
# email : leen@gmail.com
# password : 12345678


# Encypted id 

# username : maninder
# email : manavmalhotra727@gmail.com
# password : 12345678 ( original)
# crypted_password : $2b$12$xBXYdJVrYDTAZFb6lg3b8.FSdq0jA3kT05QyGVLKsifbkvaN/Qn8K

# Encrypted id

# username = Ravi 
# Ravi@gmail.com
# password = 12345678
 
 