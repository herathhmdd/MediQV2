# MO Dashboard: Show queue and actions
@app.route('/mo_dashboard')
@login_required
def mo_dashboard():
    if current_user.clinic_role != 'Medical Officer':
        abort(403)
    # Patients waiting for MO
    visits = PatientVisit.query.filter_by(status='Waiting for MO').order_by(PatientVisit.queue_number).all()
    return render_template('mo_dashboard.html', visits=visits)

# Nurse Dashboard: Show queue and actions
@app.route('/nurse_dashboard')
@login_required
def nurse_dashboard():
    if current_user.clinic_role != 'Nurse':
        abort(403)
    # Patients waiting for Nurse
    visits = PatientVisit.query.filter_by(status='Waiting for Nurse').order_by(PatientVisit.queue_number).all()
    return render_template('nurse_dashboard.html', visits=visits)
# Medical Records: List all
@app.route('/records')
@login_required
def record_list():
    records = MedicalRecord.query.order_by(MedicalRecord.record_id.desc()).all()
    return render_template('record_list.html', records=records)

# Medical Records: Create
@app.route('/records/new', methods=['GET', 'POST'])
@login_required
def create_record():
    from app.forms import MedicalRecordForm
    form = MedicalRecordForm()
    form.patient_id.choices = [(p.patient_id, p.name) for p in Patient.query.all()]
    form.visit_id.choices = [(v.visit_id, f"{v.visit_id} - {v.visit_date}") for v in PatientVisit.query.all()]
    form.examined_by.choices = [(u.user_id, u.first_name or u.username) for u in MediqUser.query.filter_by(clinic_role='Medical Officer').all()]
    if form.validate_on_submit():
        record = MedicalRecord(
            patient_id=form.patient_id.data,
            visit_id=form.visit_id.data,
            history=form.history.data,
            examination_notes=form.examination_notes.data,
            treatment_plan=form.treatment_plan.data,
            examined_by=form.examined_by.data
        )
        db.session.add(record)
        db.session.commit()
        flash('Medical record created successfully', 'success')
        return redirect(url_for('record_list'))
    return render_template('record_form.html', form=form, action='Create')

# Medical Records: View
@app.route('/records/<int:record_id>')
@login_required
def record_detail(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    return render_template('record_detail.html', record=record)

# Medical Records: Edit
@app.route('/records/<int:record_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    from app.forms import MedicalRecordForm
    form = MedicalRecordForm(obj=record)
    form.patient_id.choices = [(p.patient_id, p.name) for p in Patient.query.all()]
    form.visit_id.choices = [(v.visit_id, f"{v.visit_id} - {v.visit_date}") for v in PatientVisit.query.all()]
    form.examined_by.choices = [(u.user_id, u.first_name or u.username) for u in MediqUser.query.filter_by(clinic_role='Medical Officer').all()]
    if form.validate_on_submit():
        record.patient_id = form.patient_id.data
        record.visit_id = form.visit_id.data
        record.history = form.history.data
        record.examination_notes = form.examination_notes.data
        record.treatment_plan = form.treatment_plan.data
        record.examined_by = form.examined_by.data
        db.session.commit()
        flash('Medical record updated successfully', 'success')
        return redirect(url_for('record_list'))
    return render_template('record_form.html', form=form, action='Edit')

# Medical Records: Delete
@app.route('/records/<int:record_id>/delete', methods=['POST'])
@login_required
def delete_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    flash('Medical record deleted', 'info')
    return redirect(url_for('record_list'))
# Patient Visits: List all
@app.route('/visits')
@login_required
def visit_list():
    visits = PatientVisit.query.order_by(PatientVisit.queue_number).all()
    return render_template('visit_list.html', visits=visits)

# Patient Visits: Create
@app.route('/visits/new', methods=['GET', 'POST'])
@login_required
def create_visit():
    from app.forms import PatientVisitForm
    form = PatientVisitForm()
    # Populate select fields
    form.patient_id.choices = [(p.patient_id, p.name) for p in Patient.query.all()]
    form.mo_assigned_id.choices = [(u.user_id, u.first_name or u.username) for u in MediqUser.query.filter_by(clinic_role='Medical Officer').all()]
    form.nurse_assigned_id.choices = [(u.user_id, u.first_name or u.username) for u in MediqUser.query.filter_by(clinic_role='Nurse').all()]
    if form.validate_on_submit():
        visit = PatientVisit(
            patient_id=form.patient_id.data,
            queue_number=form.queue_number.data,
            mo_assigned_id=form.mo_assigned_id.data,
            nurse_assigned_id=form.nurse_assigned_id.data,
            visit_date=form.visit_date.data,
            status=form.status.data
        )
        db.session.add(visit)
        db.session.commit()
        flash('Patient visit created successfully', 'success')
        return redirect(url_for('visit_list'))
    return render_template('visit_form.html', form=form, action='Create')

# Patient Visits: View
@app.route('/visits/<int:visit_id>')
@login_required
def visit_detail(visit_id):
    visit = PatientVisit.query.get_or_404(visit_id)
    return render_template('visit_detail.html', visit=visit)

# Patient Visits: Edit
@app.route('/visits/<int:visit_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_visit(visit_id):
    visit = PatientVisit.query.get_or_404(visit_id)
    from app.forms import PatientVisitForm
    form = PatientVisitForm(obj=visit)
    form.patient_id.choices = [(p.patient_id, p.name) for p in Patient.query.all()]
    form.mo_assigned_id.choices = [(u.user_id, u.first_name or u.username) for u in MediqUser.query.filter_by(clinic_role='Medical Officer').all()]
    form.nurse_assigned_id.choices = [(u.user_id, u.first_name or u.username) for u in MediqUser.query.filter_by(clinic_role='Nurse').all()]
    if form.validate_on_submit():
        visit.patient_id = form.patient_id.data
        visit.queue_number = form.queue_number.data
        visit.mo_assigned_id = form.mo_assigned_id.data
        visit.nurse_assigned_id = form.nurse_assigned_id.data
        visit.visit_date = form.visit_date.data
        visit.status = form.status.data
        db.session.commit()
        flash('Patient visit updated successfully', 'success')
        return redirect(url_for('visit_list'))
    return render_template('visit_form.html', form=form, action='Edit')

# Patient Visits: Delete
@app.route('/visits/<int:visit_id>/delete', methods=['POST'])
@login_required
def delete_visit(visit_id):
    visit = PatientVisit.query.get_or_404(visit_id)
    db.session.delete(visit)
    db.session.commit()
    flash('Patient visit deleted', 'info')
    return redirect(url_for('visit_list'))
# Patients: List all
@app.route('/patients')
@login_required
def patient_list():
    if current_user.clinic_role not in ['Admin', 'Clinic Staff', 'Medical Officer', 'Nurse']:
        abort(403)
    patients = Patient.query.all()
    return render_template('patient_list.html', patients=patients)

# Patients: Create
@app.route('/patients/new', methods=['GET', 'POST'])
@login_required
def create_patient():
    if current_user.clinic_role not in ['Admin', 'Clinic Staff']:
        abort(403)
    from app.forms import PatientForm
    form = PatientForm()
    if form.validate_on_submit():
        patient = Patient(
            nic=form.nic.data,
            name=form.name.data,
            contact_info=form.contact_info.data,
            red_blue_token=form.red_blue_token.data,
            current_status=form.current_status.data
        )
        db.session.add(patient)
        db.session.commit()
        flash('Patient created successfully', 'success')
        return redirect(url_for('patient_list'))
    return render_template('patient_form.html', form=form, action='Create')

# Patients: View
@app.route('/patients/<int:patient_id>')
@login_required
def patient_detail(patient_id):
    if current_user.clinic_role not in ['Admin', 'Clinic Staff', 'Medical Officer', 'Nurse']:
        abort(403)
    patient = Patient.query.get_or_404(patient_id)
    return render_template('patient_detail.html', patient=patient)

# Patients: Edit
@app.route('/patients/<int:patient_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_patient(patient_id):
    if current_user.clinic_role not in ['Admin', 'Clinic Staff']:
        abort(403)
    patient = Patient.query.get_or_404(patient_id)
    from app.forms import PatientForm
    form = PatientForm(obj=patient)
    if form.validate_on_submit():
        patient.nic = form.nic.data
        patient.name = form.name.data
        patient.contact_info = form.contact_info.data
        patient.red_blue_token = form.red_blue_token.data
        patient.current_status = form.current_status.data
        db.session.commit()
        flash('Patient updated successfully', 'success')
        return redirect(url_for('patient_list'))
    return render_template('patient_form.html', form=form, action='Edit')

# Patients: Delete
@app.route('/patients/<int:patient_id>/delete', methods=['POST'])
@login_required
def delete_patient(patient_id):
    if current_user.clinic_role not in ['Admin', 'Clinic Staff']:
        abort(403)
    patient = Patient.query.get_or_404(patient_id)
    db.session.delete(patient)
    db.session.commit()
    flash('Patient deleted', 'info')
    return redirect(url_for('patient_list'))

from flask import render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, bcrypt, login_manager
from app.models import MediqUser, Patient, PatientVisit, MedicalRecord
from app.forms import LoginForm, RegisterForm, ResetPasswordForm, NewPasswordForm

@login_manager.user_loader
def load_user(user_id):
    return MediqUser.query.get(int(user_id))

# Home page
@app.route('/')
def home():
    return render_template('home.html')


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = MediqUser.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Admin: Register new user
@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.clinic_role != 'Admin':
        abort(403)
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = MediqUser(
            username=form.username.data,
            password_hash=hashed_pw,
            clinic_role=form.clinic_role.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            contact_number=form.contact_number.data
        )
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)


# Password reset (request)
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Placeholder: Generate token, send email
        flash('Password reset instructions sent (not implemented)', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# Password reset (set new password) - token logic placeholder
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    form = NewPasswordForm()
    if form.validate_on_submit():
        # Placeholder: Verify token, set new password
        flash('Password has been reset (not implemented)', 'success')
        return redirect(url_for('login'))
    return render_template('new_password.html', form=form)

# Dashboard (role-based)
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.clinic_role == 'Admin':
        return render_template('admin_dashboard.html')
    elif current_user.clinic_role == 'Clinic Staff':
        return render_template('staff_dashboard.html')
    elif current_user.clinic_role == 'Medical Officer':
        return render_template('mo_dashboard.html')
    elif current_user.clinic_role == 'Nurse':
        return render_template('nurse_dashboard.html')
    else:
        abort(403)


# Admin: List all users
@app.route('/users')
@login_required
def user_list():
    if current_user.clinic_role != 'Admin':
        abort(403)
    users = MediqUser.query.all()
    return render_template('user_list.html', users=users)

# Admin: View user details
@app.route('/users/<int:user_id>')
@login_required
def user_detail(user_id):
    if current_user.clinic_role != 'Admin':
        abort(403)
    user = MediqUser.query.get_or_404(user_id)
    return render_template('user_detail.html', user=user)

# Admin: Update user
@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.clinic_role != 'Admin':
        abort(403)
    user = MediqUser.query.get_or_404(user_id)
    form = RegisterForm(obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        user.clinic_role = form.clinic_role.data
        user.email = form.email.data
        if form.password.data:
            user.password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('user_list'))
    return render_template('edit_user.html', form=form, user=user)

# Admin: Delete user
@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.clinic_role != 'Admin':
        abort(403)
    user = MediqUser.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted', 'info')
    return redirect(url_for('user_list'))
