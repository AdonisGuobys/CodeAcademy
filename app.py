from flask import Flask, render_template, session, redirect, url_for
from forms import RegistrationForm, LoginForm, NoteForm
from models import User, db, Note
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'

db.init_app(app)

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
        session['user_id'] = user.id
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['logged_in'] = True
            session['user_id'] = user.id
            return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    form = NoteForm()
    if form.validate_on_submit():
        note = Note(title=form.title.data, content=form.content.data, category=form.category.data, user_id=session['user_id'])
        db.session.add(note)
        db.session.commit()
        return redirect(url_for('notes'))
    user_notes = Note.query.filter_by(user_id=session['user_id']).all()
    return render_template('notes.html', form=form, notes=user_notes)

@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        return redirect(url_for('index'))
    form = NoteForm()
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        note.category = form.category.data
        db.session.commit()
        return redirect(url_for('notes'))
    form.title.data = note.title
    form.content.data = note.content
    form.category.data = note.category
    return render_template('edit_note.html', form=form)

@app.route('/delete_note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        return redirect(url_for('index'))
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('notes'))

if __name__ == '__main__':
    app.run(debug=True)
