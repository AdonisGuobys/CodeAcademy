from flask import Flask, render_template, session, redirect, url_for, request
from forms import RegistrationForm, LoginForm, NoteForm, CategoryForm
from models import User, db, Note, Category
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

@app.route('/categories', methods=['GET', 'POST'])
def categories():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(name=form.name.data, user_id=session['user_id'])
        db.session.add(category)
        db.session.commit()
        return redirect(url_for('categories'))
    user_categories = Category.query.filter_by(user_id=session['user_id']).all()
    return render_template('categories.html', form=form, categories=user_categories)


@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    form = NoteForm()
    user_categories = Category.query.filter_by(user_id=session['user_id']).all()
    form.category.choices = [(c.id, c.name) for c in user_categories]
    if form.validate_on_submit():
        note = Note(title=form.title.data, content=form.content.data, category_id=form.category.data, user_id=session['user_id'])
        db.session.add(note)
        db.session.commit()
        return redirect(url_for('notes'))
    user_notes = Note.query.filter_by(user_id=session['user_id']).all()
    return render_template('notes.html', form=form, notes=user_notes)


@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id, category_id=None):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        return redirect(url_for('index'))
    form = NoteForm()
    user_categories = Category.query.filter_by(user_id=session['user_id']).all()
    form.category.choices = [(c.id, c.name) for c in user_categories]
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        note.category_id = form.category.data
        db.session.commit()
        if category_id:
            return redirect(url_for('view_category_notes', category_id=category_id))
        else:
            return redirect(url_for('notes'))
    form.title.data = note.title
    form.content.data = note.content
    form.category.data = note.category_id
    return render_template('edit_note.html', form=form)


@app.route('/delete_note/<int:note_id>', methods=['POST'])
def delete_note(note_id, category_id=None):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    note = Note.query.get_or_404(note_id)
    if note.user_id != session['user_id']:
        return redirect(url_for('index'))
    db.session.delete(note)
    db.session.commit()
    if category_id:
        return redirect(url_for('view_category_notes', category_id=category_id))
    else:
        return redirect(url_for('notes'))

@app.route('/category/<int:category_id>/notes', methods=['GET'])
def view_category_notes(category_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    category_notes = Note.query.filter_by(category_id=category_id, user_id=session['user_id']).all()
    return render_template('category_notes.html', notes=category_notes, category_id=category_id)

@app.route('/delete_category/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    category = Category.query.get_or_404(category_id)
    if category.user_id != session['user_id']:
        return redirect(url_for('index'))
    # All the notes in it
    Note.query.filter_by(category_id=category_id).delete()
    # The category
    db.session.delete(category)
    db.session.commit()
    return redirect(url_for('categories'))

@app.route('/search_notes', methods=['GET'])
def search_notes():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    query = request.args.get('query')
    notes = Note.query.filter(Note.user_id == session['user_id'], Note.title.like(f'%{query}%')).all()
    return render_template('search_notes.html', notes=notes)

if __name__ == '__main__':
    app.run(debug=True)
