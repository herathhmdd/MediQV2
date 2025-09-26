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
