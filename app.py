from flask import Flask, render_template, redirect, url_for, request, send_from_directory,flash
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_uploads import UploadSet, configure_uploads, IMAGES, AUDIO, ALL
from email_validator import validate_email, EmailNotValidError
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['UPLOADED_FILES_DEST'] = 'uploads'
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

files = UploadSet('files', ALL)
configure_uploads(app, files)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    return render_template('index.html', upload_url=url_for('upload'), logout_url=url_for('logout'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Username or password is incorrect', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate email
        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError as e:
            flash(str(e), 'danger')
            return redirect(url_for('register'))

        # Check if email or username already exists
        if User.query.filter_by(email=email).first() is not None:
            flash('Email address already in use', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first() is not None:
            flash('Username already in use', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return 'No file part', 400

    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    if file and file.filename:
        filename = files.save(file)
        url = url_for('uploaded_file', setname='files', filename=filename)
        room = request.form.get('room')
        file_type = request.form.get('file_type')
        socketio.emit('file', {'url': url, 'type': file_type, 'user': current_user.username, 'room': room}, to=room)
        return '', 204
    return 'Failed to upload file', 500

@app.route('/uploads/<setname>/<filename>')
def uploaded_file(setname, filename):
    return send_from_directory(app.config['UPLOADED_FILES_DEST'], filename)

@socketio.on('join')
def handle_join(data):
    room = data['room']
    join_room(room)
    send({'msg': f'{current_user.username} has entered the room.', 'user': current_user.username}, to=room)

@socketio.on('leave')
def handle_leave(data):
    room = data['room']
    leave_room(room)
    send({'msg': f'{current_user.username} has left the room.', 'user': current_user.username}, to=room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    send({'msg': data['msg'], 'user': current_user.username}, to=room)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    #db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
