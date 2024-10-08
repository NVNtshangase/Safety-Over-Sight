from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import Enum, Time

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'User'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(50), nullable=False)
    password_reset_token = db.Column(db.String(128), nullable=True)
    role = db.Column(db.String(10), nullable=False)
    
    parent_id = db.Column(db.Integer, db.ForeignKey('Parent.ParentID', ondelete='CASCADE'), unique=True, nullable=True)  
    authority_id = db.Column(db.Integer, db.ForeignKey('SchoolAuthority.AuthorityID', ondelete='CASCADE'), unique=True, nullable=True)  

    parent = db.relationship('Parent', backref='user', uselist=False)  
    school_authority = db.relationship('SchoolAuthority', backref='user', uselist=False)  

    def __repr__(self):
        return f'<User {self.username}>'

class Parent(db.Model):
    __tablename__ = 'Parent'
    
    ParentID = db.Column(db.Integer, primary_key=True)
    Parent_Name = db.Column(db.String(50), nullable=False)
    Parent_Surname = db.Column(db.String(50), nullable=False)
    Parent_EmailAddress = db.Column(db.String(30), unique=True, nullable=False)
    Parent_CellPhoneNumber = db.Column(db.String(15), unique=True, nullable=False)
    
    # Relationships 
    students = db.relationship('Student', backref='parent', lazy=True, cascade='all, delete-orphan')  
    notifications = db.relationship('Notification', backref='parent', lazy=True, cascade='all, delete-orphan')

class Student(db.Model):
    __tablename__ = 'Student'
    
    StudentID = db.Column(db.Integer, primary_key=True)
    Student_Name = db.Column(db.String(50), nullable=False)
    Student_Surname = db.Column(db.String(50), nullable=False)
    Student_ID_NO = db.Column(db.String(20), unique=True, nullable=False)
    Student_QR_Code = db.Column(db.String(100), unique=True, nullable=False)
    ParentID = db.Column(db.Integer, db.ForeignKey('Parent.ParentID', ondelete='CASCADE'), nullable=False)  

    scan_records = db.relationship('ScanRecord', backref='student', lazy=True, cascade='all, delete-orphan')

class SchoolAuthority(db.Model):
    __tablename__ = 'SchoolAuthority'
    
    AuthorityID = db.Column(db.Integer, primary_key=True)
    Authority_Name = db.Column(db.String(50), nullable=False)
    Authority_Surname = db.Column(db.String(50), nullable=False)
    Authority_EmailAddress = db.Column(db.String(30), unique=True, nullable=False)
    Authority_Role = db.Column(db.String(50))

    checkpoints = db.relationship('CheckPoint', backref='authority', lazy=True, cascade='all, delete-orphan')

class CheckPoint(db.Model):
    __tablename__ = 'CheckPoint'
    
    CheckpointID = db.Column(db.Integer, primary_key=True)
    Checkpoint_Location = db.Column(db.String(50), nullable=False)
    Checkpoint_EndTime = db.Column(db.DateTime, nullable=False)
    IsCurrent = db.Column(db.Boolean, default=False)
    
    AuthorityID = db.Column(db.Integer, db.ForeignKey('SchoolAuthority.AuthorityID', ondelete='CASCADE'), nullable=True)

    scan_records = db.relationship('ScanRecord', backref='checkpoint', lazy=True, cascade='all, delete-orphan')

class ScanRecord(db.Model):
    __tablename__ = 'ScanRecord'
    
    ScanID = db.Column(db.Integer, primary_key=True)
    Scan_Time = db.Column(db.DateTime, default=db.func.current_timestamp())
    Scan_Status = db.Column(db.String(10), nullable=False)
    StudentID = db.Column(db.Integer, db.ForeignKey('Student.StudentID', ondelete='CASCADE'), nullable=False)
    CheckpointID = db.Column(db.Integer, db.ForeignKey('CheckPoint.CheckpointID', ondelete='CASCADE'), nullable=False)

    notification = db.relationship('Notification', backref='scan_record', uselist=False, cascade='all, delete-orphan')

class Notification(db.Model):
    __tablename__ = 'Notification'
    
    NotificationID = db.Column(db.Integer, primary_key=True)
    Notification_SendTime = db.Column(db.DateTime, default=db.func.current_timestamp())
    Notification_Message = db.Column(db.Text, nullable=False)
    ParentID = db.Column(db.Integer, db.ForeignKey('Parent.ParentID', ondelete='CASCADE'), nullable=True)

    ScanID = db.Column(db.Integer, db.ForeignKey('ScanRecord.ScanID', ondelete='CASCADE'), unique=True, nullable=False)