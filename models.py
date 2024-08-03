from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    bio = Column(Text)

    messages = relationship('Message', back_populates='user')
    room_users = relationship('RoomUser', back_populates='user')

class Room(db.Model):
    __tablename__ = 'room'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    creator_id = Column(Integer, ForeignKey('user.id'))
    creator = relationship('User')  # Relationship for creator

    room_users = relationship('RoomUser', back_populates='room')
    messages = relationship('Message', back_populates='room')

class Message(db.Model):
    __tablename__ = 'message'
    id = Column(Integer, primary_key=True)
    content = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    room_id = Column(Integer, ForeignKey('room.id'))
    timestamp = Column(DateTime, default=datetime.utcnow)
    audio_file = Column(String(200), nullable=True)
    image_file = Column(String(200), nullable=True)

    # Define relationships
    user = relationship('User', back_populates='messages')
    room = relationship('Room', back_populates='messages')

class RoomUser(db.Model):
    __tablename__ = 'room_user'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    room_id = Column(Integer, ForeignKey('room.id'))

    user = relationship('User', back_populates='room_users')
    room = relationship('Room', back_populates='room_users')
