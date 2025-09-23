from app import db
from flask_login import UserMixin
from datetime import date

class MediqUser(db.Model, UserMixin):
    __tablename__ = 'mediq_users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    clinic_role = db.Column(db.String(50), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    contact_number = db.Column(db.String(15))
    email = db.Column(db.String(100), unique=True)

class Patient(db.Model):
    __tablename__ = 'patients'
    patient_id = db.Column(db.Integer, primary_key=True)
    nic = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    contact_info = db.Column(db.Text)
    red_blue_token = db.Column(db.String(50))
    current_status = db.Column(db.String(50))

class PatientVisit(db.Model):
    __tablename__ = 'patient_visits'
    visit_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.patient_id'), nullable=False)
    queue_number = db.Column(db.Integer, nullable=False)
    mo_assigned_id = db.Column(db.Integer, db.ForeignKey('mediq_users.user_id'))
    nurse_assigned_id = db.Column(db.Integer, db.ForeignKey('mediq_users.user_id'))
    visit_date = db.Column(db.Date, default=date.today)
    status = db.Column(db.String(50))

class MedicalRecord(db.Model):
    __tablename__ = 'medical_records'
    record_id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.patient_id'), nullable=False)
    visit_id = db.Column(db.Integer, db.ForeignKey('patient_visits.visit_id'), nullable=False)
    history = db.Column(db.Text)
    examination_notes = db.Column(db.Text)
    treatment_plan = db.Column(db.Text)
    examined_by = db.Column(db.Integer, db.ForeignKey('mediq_users.user_id'))
