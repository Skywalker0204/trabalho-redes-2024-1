from flask import Flask, render_template, redirect, url_for, request, jsonify, send_from_directory, flash
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from email_validator import validate_email, EmailNotValidError
import os
from datetime import datetime
import logging
from models import db, User, Room, Message, RoomUser  

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  

db.init_app(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = '/login'
migrate = Migrate(app, db)
logging.basicConfig(level=logging.DEBUG)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('room_selection'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        try:
            validate_email(email)
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('room_selection'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {e}', 'danger')
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/user_profile/<username>')
@login_required
def user_profile(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return render_template('user_profile.html', user=user)
    flash('User not found', 'danger')
    return redirect(url_for('room_selection'))


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.username = request.form['username']
        current_user.email = request.form['email']
        current_user.bio = request.form['bio']
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('room_selection'))
    return render_template('edit_profile.html', user=current_user)

@app.route('/room_selection')
def room_selection():
    
    rooms = Room.query.all()

    
    users = User.query.all()

    
    all_rooms = Room.query.all()

    return render_template('room_selection.html', rooms=rooms, users=users, all_rooms=all_rooms)

@app.route('/create_room', methods=['GET', 'POST'])
@login_required
def create_room():
    if request.method == 'POST':
        room_name = request.form['room_name']
        if Room.query.filter_by(name=room_name).first():
            flash('Room already exists', 'danger')
            return redirect(url_for('create_room'))
        new_room = Room(name=room_name, creator_id=current_user.id)
        db.session.add(new_room)
        db.session.commit()
        db.session.add(RoomUser(room_id=new_room.id, user_id=current_user.id))
        db.session.commit()
        flash('Room created', 'success')
        return redirect(url_for('create_room'))
    created_rooms = Room.query.filter_by(creator_id=current_user.id).all()
    return render_template('create_room.html', created_rooms=created_rooms)

@app.route('/rename_room/<int:room_id>', methods=['POST'])
@login_required
def rename_room(room_id):
    room = Room.query.get(room_id)
    if room and room.creator_id == current_user.id:
        new_name = request.form['new_name']
        if Room.query.filter_by(name=new_name).first():
            flash('Room name already taken', 'danger')
            return redirect(url_for('create_room'))
        room.name = new_name
        db.session.commit()
        flash('Room renamed', 'success')
        return redirect(url_for('create_room'))
    flash('Not authorized', 'danger')
    return redirect(url_for('create_room'))

@app.route('/ban_user/<int:room_id>', methods=['POST'])
@login_required
def ban_user(room_id):
    room = Room.query.get(room_id)
    if room and room.creator_id == current_user.id:
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            room_user = RoomUser.query.filter_by(room_id=room.id, user_id=user.id).first()
            if room_user:
                db.session.delete(room_user)
                db.session.commit()
                flash(f'{username} has been banned from the room', 'success')
                return redirect(url_for('create_room'))
            flash('User is not a member of this room', 'danger')
            return redirect(url_for('create_room'))
        flash('User not found', 'danger')
        return redirect(url_for('create_room'))
    flash('Not authorized', 'danger')
    return redirect(url_for('create_room'))

@app.route('/request_room', methods=['POST'])
@login_required
def request_room():
    room_name = request.form.get('room_name')
    room = Room.query.filter_by(name=room_name).first()
    if room:
        db.session.add(RoomUser(room_id=room.id, user_id=current_user.id))
        db.session.commit()
        flash('Requested to join the room', 'success')
        return redirect(url_for('room_selection'))
    flash('Room not found', 'danger')
    return redirect(url_for('room_selection'))

@app.route('/chat_room/<int:room_id>', methods=['GET'])
@login_required
def chat_room(room_id):
    room = Room.query.get_or_404(room_id)
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).all()

    
    user_details = {user.id: {
        'username': user.username,
        'email': user.email,
        'bio': user.bio
    } for user in User.query.all()}

    return render_template('chat_room.html', room=room, messages=messages, room_id=room_id, user_details=user_details)


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    file = request.files['file']
    room_id = request.form.get('room_id')

    if not room_id:
        flash('Room ID missing', 'danger')
        return redirect(url_for('chat_room', room_id=room_id))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        file_url = url_for('uploaded_file', filename=filename)
        message = Message(
            user_id=current_user.id,
            room_id=room_id,
            content='',
            audio_file=filename if file.filename.lower().endswith('.mp3') else None,
            image_file=filename if file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')) else None,
            timestamp=datetime.utcnow()
        )
        db.session.add(message)
        db.session.commit()

    return redirect(url_for('chat_room', room_id=room_id))

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form.get('message_content')
    room_id = request.form.get('room_id')
    audio_file = request.files.get('audio_file')
    image_file = request.files.get('image_file')

    message = Message(
        user_id=current_user.id,
        room_id=room_id,
        content=content,
        timestamp=datetime.utcnow()
    )
    
    if audio_file and allowed_file(audio_file.filename):
        filename = secure_filename(audio_file.filename)
        audio_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        message.audio_file = filename
    if image_file and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        message.image_file = filename

    db.session.add(message)
    db.session.commit()

    return redirect(url_for('chat_room', room_id=room_id))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@socketio.on('connect')
def handle_connect():
    emit('status', {'msg': f'{current_user.username} has joined the chat'})

@socketio.on('disconnect')
def handle_disconnect():
    emit('status', {'msg': f'{current_user.username} has left the chat'})

@app.route('/delete_room/<int:room_id>', methods=['POST'])
@login_required
def delete_room(room_id):
    room = Room.query.get(room_id)
    if room and room.creator_id == current_user.id:
        db.session.delete(room)
        db.session.commit()
        flash('Room deleted successfully', 'success')
        return redirect(url_for('create_room'))
    flash('Not authorized or room not found', 'danger')
    return redirect(url_for('create_room'))


@socketio.on('send_message')
def handle_message(data):
    room = Room.query.get(data['room_id'])
    if room:
        message = Message(
            user_id=current_user.id,
            room_id=data['room_id'],
            content=data['content'],
            timestamp=datetime.utcnow()
        )
        db.session.add(message)
        db.session.commit()
        emit('receive_message', {
            'user': current_user.username,
            'message': data['content'],
            'timestamp': message.timestamp
        }, room=data['room_id'])

@socketio.on('join')
def on_join(data):
    room = Room.query.get(data['room_id'])
    if room:
        join_room(data['room_id'])
        emit('status', {'msg': f'{current_user.username} has joined the room.'}, room=data['room_id'])

@socketio.on('leave')
def on_leave(data):
    room = Room.query.get(data['room_id'])
    if room:
        leave_room(data['room_id'])
        emit('status', {'msg': f'{current_user.username} has left the room.'}, room=data['room_id'])

def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'mp3'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

if __name__ == '__main__':

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    socketio.run(app, host='0.0.0.0', port=5000)
