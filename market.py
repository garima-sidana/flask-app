from flask import Flask,render_template,redirect,url_for,flash,request
from flask_sqlalchemy import SQLAlchemy 
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import Length,EqualTo,Email,DataRequired,ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager,login_user,UserMixin,logout_user,login_required

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///market.db'
db=SQLAlchemy(app)
app.config['SECRET_KEY']="6929f9ae3a61514d647de5a9473f315f4da59d983f4d88124a32f0eb30682261"
bcrypt=Bcrypt(app)
login_manager=LoginManager(app)
login_manager.login_view="login_page"
login_manager.login_message_category="info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) 

class Items(db.Model):
    ID=db.Column(db.Integer,nullable=False,unique=True,primary_key=True)
    Name=db.Column(db.String(length=30),nullable=False,unique=True)
    Barcode=db.Column(db.String(length=12),nullable=False,unique=True)
    Price=db.Column(db.Integer,nullable=False,unique=False)
    Details=db.Column(db.String(length=1000),nullable=False,unique=True)
    owner=db.Column(db.Integer(),db.ForeignKey('user.id'))

    def __repr__(self):
         return f'Item {self.Name}'
    
    
    
class User(db.Model,UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    budget = db.Column(db.Integer(), nullable=False, default=1000)
    items = db.relationship('Items', backref='owned_user', lazy=True)

    def __repr__(self):
        return f'User {self.username}'
    
    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correct(self,attempted_password):
        return bcrypt.check_password_hash(self.password_hash,attempted_password)

class Register(FlaskForm):
    def validate_username(self, username_to_check):
        user = User.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username already exists! Please try a different username')

    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('Email Address already exists! Please try a different email address')


    username=StringField(label='Username',validators=[Length(min=4,max=20),DataRequired()])
    email_address=StringField(label='Email-address',validators=[Email(),DataRequired()])
    password1=PasswordField(label='Set your password',validators=[Length(min=4),DataRequired()])
    password2=PasswordField(label='Confirm your password',validators=[EqualTo('password1'),DataRequired()])
    submit=SubmitField(label='Register')

class Login(FlaskForm):
    username=StringField(label='Username',validators=[DataRequired()])
    password=PasswordField(label='Password',validators=[DataRequired()])
    submit=SubmitField(label='Log in')

class PurchaseItemForm(FlaskForm):
    submit = SubmitField(label='Purchase Item!')

class SellItemForm(FlaskForm):
    submit = SubmitField(label='Sell Item!')


@app.route("/")
@app.route("/home")
def home_page():
    return render_template('home.html')

@app.route('/market')
@login_required
def market_page():
    items = Items.query.all()
    purchase_form=PurchaseItemForm()
    sell_form=SellItemForm()
    return render_template('market.html',items=items,purchase_form=purchase_form,sell_form=sell_form)

@app.route('/register',methods=['GET','POST'])
def register_page():
     form=Register()
     if form.validate_on_submit():
        user_to_create = User(username=form.username.data,
                              email_address=form.email_address.data,
                              password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()

        login_user(user_to_create)
        flash(f'Account created successfullly! You are now logged in as {user_to_create.username}',category="success" )
        return redirect(url_for('market_page'))
     
     if form.errors != {}: 
        for field , err_msg in form.errors.items():
            flash(f'There was an error with creating a user: {err_msg}',category='danger')
          
     return render_template('register.html',form=form)

@app.route('/login',methods=['GET','POST'])
def login_page():
    form=Login()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correct(
                attempted_password=form.password.data
        ):
            login_user(attempted_user)
            flash(f'Success! You are logged in as: {attempted_user.username}', category='success')
            return redirect(url_for('market_page'))
        else:
            flash('Username and password are not match! Please try again', category='danger')

    return render_template('login.html',form=form)

@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have been logged out!",category="info")
    return redirect(url_for('home_page'))



with app.app_context():
        print("Creating database tables...")
        db.create_all()

if __name__ == "__main__":
    app.run(debug=True) 