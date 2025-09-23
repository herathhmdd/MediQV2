from flask import render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, bcrypt, login_manager
from app.models import MediqUser, Patient, PatientVisit, MedicalRecord

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = MediqUser.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['clinic_role']
        email = request.form['email']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = MediqUser(username=username, password_hash=hashed_pw, clinic_role=role, email=email)
        db.session.add(user)
        db.session.commit()
        flash('User registered successfully', 'success')
        return redirect(url_for('user_list'))
    return render_template('register.html')

# Password reset (request)
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Placeholder: Implement email sending and token logic
    if request.method == 'POST':
        flash('Password reset instructions sent (not implemented)', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

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

# ... More CRUD and workflow routes will be added ...
