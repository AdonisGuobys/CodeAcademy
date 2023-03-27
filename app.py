from flask import Flask, render_template, session, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from forms import RegistrationForm, LoginForm, CheckForm, GroupForm
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)

    def __repr__(self):
        return '<User %r>' % self.username
    
class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True, nullable=False)
    users = db.relationship('User', backref='group', lazy=True)

    def __repr__(self):
        return '<Group %r>' % self.name
    
class Check(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)

    def __repr__(self):
        return '<Check %r>' % self.name    
    
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)
        user = User(username=username, password=hashed_password.decode())
        db.session.add(user)
        db.session.commit()
        session['logged_in'] = True
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode(), user.password.encode()):
            session['logged_in'] = True
            return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/bill', methods=['GET', 'POST'])
def bill():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    form = CheckForm()
    if form.validate_on_submit():
        name = form.name.data
        amount = form.amount.data
        check = Check(name=name, amount=amount)
        db.session.add(check)
        db.session.commit()
    checks = Check.query.order_by(Check.timestamp.desc()).all()
    return render_template('bill.html', form=form, checks=checks)

@app.route('/group', methods=['GET', 'POST'])
def group():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    form = GroupForm()
    if form.validate_on_submit():
        group_name = form.group_name.data
        group = Group.query.filter_by(name=group_name).first()
        if not group:
            new_group = Group(name=group_name)
            db.session.add(new_group)
            db.session.commit()
        return redirect(url_for('group'))  
    groups = Group.query.all()  
    return render_template('group.html', form=form, groups=groups)  

@app.route('/group/<int:group_id>', methods=['GET', 'POST'])
def group_detail(group_id):
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    group = Group.query.get(group_id)
    form = CheckForm()
    if form.validate_on_submit():
        name = form.name.data
        amount = form.amount.data
        check = Check(name=name, amount=amount, group_id=group_id)
        db.session.add(check)
        db.session.commit()
        return redirect(url_for('group_detail', group_id=group_id))
    checks = Check.query.filter_by(group_id=group_id).order_by(Check.timestamp.desc()).all()
    return render_template('group_detail.html', group=group, form=form, checks=checks)