from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from datetime import date
class MedicalRecordForm(FlaskForm):
    patient_id = SelectField('Patient', coerce=int, validators=[DataRequired()])
    visit_id = SelectField('Visit', coerce=int, validators=[DataRequired()])
    history = TextAreaField('History')
    examination_notes = TextAreaField('Examination Notes', validators=[DataRequired()])
    treatment_plan = TextAreaField('Treatment Plan', validators=[DataRequired()])
    examined_by = SelectField('Examined By', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Save')
class PatientVisitForm(FlaskForm):
    patient_id = SelectField('Patient', coerce=int, validators=[DataRequired()])
    queue_number = IntegerField('Queue Number', validators=[DataRequired()])
    mo_assigned_id = SelectField('MO Assigned', coerce=int)
    nurse_assigned_id = SelectField('Nurse Assigned', coerce=int)
    visit_date = DateField('Visit Date', validators=[DataRequired()], default=date.today)
    status = SelectField('Status', choices=[('waiting', 'Waiting'), ('in_consultation', 'In Consultation'), ('with_nurse', 'With Nurse'), ('at_pharmacy', 'At Pharmacy'), ('completed', 'Completed')], validators=[DataRequired()])
    submit = SubmitField('Save')
class PatientForm(FlaskForm):
    nic = StringField('NIC', validators=[DataRequired(), Length(max=50)])
    name = StringField('Name', validators=[DataRequired(), Length(max=255)])
    contact_info = StringField('Contact Info', validators=[Length(max=255)])
    red_blue_token = SelectField('Token', choices=[('Red', 'Red'), ('Blue', 'Blue')], validators=[DataRequired()])
    submit = SubmitField('Save')
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, Length, EqualTo
import re
from wtforms import ValidationError

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

def validate_sri_lanka_contact(form, field):
    pattern = r"^\+94\d{9}$"
    if not re.match(pattern, field.data):
        raise ValidationError('Contact number must be in the format +94XXXXXXXXX (9 digits after +94)')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=100)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=100)])
    contact_number = StringField('Contact Number', validators=[DataRequired(), validate_sri_lanka_contact])
    clinic_role = SelectField('Role', choices=[('Clinic Staff','Clinic Staff'),('Medical Officer','Medical Officer'),('Nurse','Nurse'),('Admin','Admin')], validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')

class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class NewPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
