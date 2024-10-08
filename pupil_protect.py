from flask import (Flask, render_template,flash, redirect, url_for, flash, jsonify,make_response, request)
from flask_migrate import Migrate
from flask_login import (LoginManager, login_user, login_required, logout_user, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from functools import wraps
from dotenv import load_dotenv
import os, logging, pytz, re, smtplib,phonenumbers, qrcode, pdfkit
from datetime import datetime, timedelta
from models.user import (User, db, Parent, SchoolAuthority, Student, ScanRecord, Notification, CheckPoint)
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration from environment variables
SENDGRID_USERNAME = os.environ.get('SENDGRID_USERNAME')
SENDGRID_PASSWORD = os.environ.get('SENDGRID_PASSWORD')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')

app = Flask(__name__)
load_dotenv()  # Load environment variables from .env file
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')

app.config['SECRET_KEY'] = 'sedrgyuhjbgcftygufty3454guhftyugtfy6gyuh'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfKg1kqAAAAAMD2WHRzPQuqofKxvDG5GqlCZtVg'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LfKg1kqAAAAALjYl197cM1F3RPmr5dGziPW2Mao'

db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Route for Home Page
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

# Route for About Page
@app.route('/about')
def about():
    return render_template('about.html')

# Password complexity check
def validate_password(password):
    if len(password) < 6:
        return "Password must be at least 6 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return None

# Username validation to check if it's an email
def validate_username(username):
    # Check if the username (email) is in a valid format
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", username):
        return "Username must be a valid email address."
    return None

# Route for Signup Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()
        role = request.form['role']

        # Username validation
        username_error = validate_username(username)
        if username_error:
            flash(username_error, 'error')
            return render_template('signup.html', username=username, role=role)

        # Check if username is already taken
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('signup.html', username=username, role=role)

        # Password validation
        password_error = validate_password(password)
        if password_error:
            flash(password_error, 'error')
            return render_template('signup.html', username=username, role=role)

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return render_template('signup.html', username=username, role=role)

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Add new user to the database
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')

        # Log in the user immediately after signup
        login_user(new_user)

        # Redirect based on user role
        return redirect(url_for('create_profile'))

    return render_template('signup.html')

# Function to validate phone number (international format)
def is_valid_phone_number(phone_number):
    try:
        # The phone_number should include the country code, e.g., +1234567890
        parsed_number = phonenumbers.parse(phone_number, None)  # 'None' allows it to determine the region based on the number
        return phonenumbers.is_valid_number(parsed_number)
    except phonenumbers.NumberParseException:
        return False

import secrets
def generate_password_reset_token(user):
    # Use a secure token generator like secrets or uuid
    token = secrets.token_urlsafe(16)
    # Store the token in the user's session or database
    user.password_reset_token = token
    db.session.commit()
    return token

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        
        # Validate the username format
        validation_error = validate_username(username)
        if validation_error:
            flash(validation_error, 'error')
            return render_template('login.html') 
        
        # Check if the username exists in the database
        user = User.query.filter_by(username=username).first()
        if user:
            # Generate a password reset token
            token = generate_password_reset_token(user)
            # Send a password reset email to the user
            send_password_reset_email(user, token)
            flash('Password reset email sent successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid username or email address.', 'error')
            return render_template('login.html') 
    
    return render_template('login.html')

def send_password_reset_email(user, token):
    # Create a password reset email template
    template = render_template('password_reset_email.html', user=user, token=token)
    # Send the email using your email service
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = user.username
    msg['Subject'] = 'Password Reset Request'
    msg.attach(MIMEText(template, 'html'))
    with smtplib.SMTP('smtp.sendgrid.net', 587) as server:
        server.starttls()  # Enable TLS
        server.login(SENDGRID_USERNAME, SENDGRID_PASSWORD)
        server.sendmail(SENDER_EMAIL, user.username, msg.as_string())

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        user = User.query.filter_by(password_reset_token=token).first()
        if user:
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            # Validate the new password
            if new_password != confirm_password:
                flash('Passwords do not match. Please try again.', 'error')
                return render_template('reset_password.html', token=token)
            # Hash the new password
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            # Update the user's password
            user.password = hashed_password
            db.session.commit()
            flash('Password reset successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid token or password reset request.', 'error')
            return render_template('reset_password.html', token=token)
    return render_template('reset_password.html', token=token)

# Route for Create Profile
@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    if request.method == 'POST':
        email = current_user.username  # Use the username as the email
        
        if current_user.role == 'Parent':
            # Get other form data
            name = request.form.get('name', '').strip().capitalize()
            surname = request.form.get('surname', '').strip().capitalize()
            phone_number = request.form.get('phone_number', '')
            
            # Validate phone number (no need to validate email as it's from current_user.username)
            if not is_valid_phone_number(phone_number):
                flash('Invalid phone number format.', 'error')
                return render_template('create_profile.html', name=name, surname=surname, phone_number=phone_number, email=email)
            
            # Check if the phone number already exists in the Parent table
            existing_parent = Parent.query.filter_by(Parent_CellPhoneNumber=phone_number).first()
            if existing_parent:
                flash('This phone number is already registered.', 'error')
                return render_template('create_profile.html', name=name, surname=surname, phone_number=phone_number, email=email)
            
            if current_user.parent_id is None:
                new_parent = Parent(
                    Parent_Name=name,
                    Parent_Surname=surname,
                    Parent_EmailAddress=email,  # Use the email from current_user
                    Parent_CellPhoneNumber=phone_number
                )
                db.session.add(new_parent)
                db.session.commit()
                current_user.parent_id = new_parent.ParentID  # Link to user
                db.session.commit()
                flash('Parent profile created successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('You have already created a profile.', 'warning')
                return redirect(url_for('dashboard'))

        elif current_user.role == 'School Authority':
            # Get other form data
            authority_name = request.form.get('authority_name', '')
            authority_surname = request.form.get('authority_surname', '')
            role = request.form.get('role', '')
            
            if current_user.authority_id is None:
                new_authority = SchoolAuthority(
                    Authority_Name=authority_name,
                    Authority_Surname=authority_surname,
                    Authority_EmailAddress=email,  # Use the email from current_user
                    Authority_Role=role
                )
                db.session.add(new_authority)
                db.session.commit()
                current_user.authority_id = new_authority.AuthorityID
                db.session.commit()
                flash('Authority profile created successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('You have already created a profile.', 'warning')
                return redirect(url_for('dashboard'))

    return render_template('create_profile.html', email=current_user.username)

@app.route('/dashboard')
@login_required  # Ensure that only logged-in users can access this route
def dashboard():
    # Check user type and retrieve relevant information
    if current_user.role == 'Parent':
        parent = Parent.query.get(current_user.parent_id)
        return render_template('dashboard.html', user=current_user, parent=parent)
    
    elif current_user.role == 'School Authority':
        authority = SchoolAuthority.query.get(current_user.authority_id)
        return render_template('dashboard.html', user=current_user, authority=authority)

    # Handle other user roles or types if necessary
    flash('Access to this dashboard is restricted to authorized users.')
    return redirect(url_for('home'))

# Route for Login Page
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    recaptcha = RecaptchaField()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Login failed. Check your credentials.')
    elif request.method == 'POST':  # Only show flash on POST request if the form is not valid
        flash('Login failed. Check your credentials.')

    return render_template('login.html', form=form)

# Route for Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))
 
 #Add_Student/s

def luhn_check_algorithm(id_number):
    """Validate South African ID number using the Luhn algorithm."""
    total = 0
    reverse_id = id_number[::-1]
    
    for i, digit in enumerate(reverse_id):
        n = int(digit)
        if i % 2 == 1:  # Double every second digit
            n *= 2
            if n > 9:  # If the result is greater than 9, subtract 9
                n -= 9
        total += n
    
    return total % 10 == 0  # Valid if the total modulo 10 is zero

def validate_id_number_with_service(id_no, name, surname):
    # logic to validate the ID number against the external service
    # an API request to verify the ID number and names
    # Return True if valid, False if not, or None if an error occurred
    return True  

#add-student
@app.route('/add_student', methods=['GET', 'POST'])
@login_required  # Ensure user is logged in
def add_student():
    # Check if the logged-in user is a parent
    if current_user.role != 'Parent':
        flash("You are not authorized to add a student.", "danger")
        return redirect(url_for('home'))

    # Fetch the Parent object associated with the logged-in user
    parent = Parent.query.filter_by(ParentID=current_user.parent_id).first()

    if not parent:
        flash("No parent record found for this user.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Retrieve and sanitize the form data
        student_name = request.form['student_name'].strip().capitalize()
        student_surname = request.form['student_surname'].strip().capitalize()
        student_id_no = request.form['student_id_no'].strip()

        # Validate that name and surname contain only alphabetic characters, hyphens, or apostrophes
        name_pattern = re.compile(r"^[A-Za-z\s'-]+$")
        if not name_pattern.match(student_name) or not name_pattern.match(student_surname):
            flash('Name and surname must contain only alphabetic characters, hyphens, or apostrophes.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        # Validate the ID number contains only digits
        if not student_id_no.isdigit():
            flash('Student ID Number must contain only numeric characters.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        # Validate the length of student_id_no (must be 13 digits)
        if len(student_id_no) != 13:
            flash('Student ID Number must be exactly 13 characters long.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        # Check if the ID number already exists in the database
        existing_student = Student.query.filter_by(Student_ID_NO=student_id_no).first()
        if existing_student:
            flash('This ID Number already exists in the database.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        # Validate the ID number using the Luhn algorithm
        if not luhn_check_algorithm(student_id_no):
            flash('Student ID Number is invalid according to the Luhn algorithm.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        # Validate birth year, month, and day from the ID number
        birth_year = int(student_id_no[0:2])
        birth_month = int(student_id_no[2:4])
        birth_day = int(student_id_no[4:6])

        # Correct the year to 1900s or 2000s
        if birth_year > 24:
            birth_year += 1900
        else:
            birth_year += 2000

        # Validate month
        if birth_month < 1 or birth_month > 12:
            flash('Invalid month in the Student ID Number.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        # Validate day based on month
        if birth_month in [1, 3, 5, 7, 8, 10, 12]:
            if birth_day < 1 or birth_day > 31:
                flash('Invalid day in the Student ID Number for the given month.', 'danger')
                return render_template('add_student.html', 
                                       student_name=student_name, 
                                       student_surname=student_surname, 
                                       student_id_no=student_id_no, 
                                       parent=parent)
        elif birth_month in [4, 6, 9, 11]:
            if birth_day < 1 or birth_day > 30:
                flash('Invalid day in the Student ID Number for the given month.', 'danger')
                return render_template('add_student.html', 
                                       student_name=student_name, 
                                       student_surname=student_surname, 
                                       student_id_no=student_id_no, 
                                       parent=parent)
        elif birth_month == 2:
            if birth_day < 1 or birth_day > 29:
                flash('Invalid day in the Student ID Number for February.', 'danger')
                return render_template('add_student.html', 
                                       student_name=student_name, 
                                       student_surname=student_surname, 
                                       student_id_no=student_id_no, 
                                       parent=parent)

        age = datetime.now().year - birth_year
        if age > 100:
            flash('Student cannot be older than 100 years.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        # Validate the ID number with an external service
        validation_result = validate_id_number_with_service(student_id_no, student_name, student_surname)
        if validation_result is None:
            flash('Error validating ID number with the external service.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        if not validation_result:
            flash('ID number does not match the provided name.', 'danger')
            return render_template('add_student.html', 
                                   student_name=student_name, 
                                   student_surname=student_surname, 
                                   student_id_no=student_id_no, 
                                   parent=parent)

        # Generate QR code
        qr_data = f"{student_id_no}|{student_name}|{student_surname}"
        qr = qrcode.make(qr_data)
        qr_code_filename = f"{student_id_no}.png"
        qr_code_path = os.path.join('static/qr_codes', qr_code_filename)
        qr.save(qr_code_path)

        # Create new student record and link to parent
        new_student = Student(
            Student_Name=student_name,
            Student_Surname=student_surname,
            Student_ID_NO=student_id_no,
            Student_QR_Code=qr_code_filename,
            ParentID=parent.ParentID  # Link to the logged-in parent's ID
        )

        try:
            db.session.add(new_student)
            db.session.commit()
            flash("Student added successfully!", "success")
            return redirect(url_for('add_student_success', student_id=new_student.StudentID))
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding student: {str(e)}", "danger")
            return redirect(url_for('dashboard1'))

    # Render the form template
    return render_template('add_student.html', parent=parent)

@app.route('/student/<int:student_id>', methods=['GET'])
@login_required
def add_student_success(student_id):
    # Check if the logged-in user is a parent
    if current_user.role != 'Parent':
        flash("You are not authorized to view this student.", "danger")
        return redirect(url_for('home'))

    # Query the student using the provided student_id
    student = Student.query.filter_by(StudentID=student_id).first()

    if not student:
        flash("Student not found.", "danger")
        return redirect(url_for('home'))

    # Render the student view template with student details
    return render_template('add_student_success.html', student=student)

# Profile
@app.route('/profile')
@login_required
def user_profile():
    # Fetch the profile based on the user's role
    if current_user.role == 'Parent':
        profile = Parent.query.filter_by(ParentID=current_user.parent_id).first()
    elif current_user.role == 'School Authority':
        profile = SchoolAuthority.query.filter_by(AuthorityID=current_user.authority_id).first()
    else:
        flash('You do not have access to this page.')
        return redirect(url_for('home'))

    # Ensure the profile exists before rendering
    if profile is None:
        flash('Profile not found. Please create a profile first.')
        return redirect(url_for('create_profile'))

    return render_template('user_profile.html', profile=profile, role=current_user.role)

#View parent Student/s
@app.route('/my-children', methods=['GET', 'POST'])
@login_required
def my_students():
    # Fetch all children associated with the current parent
    students = Student.query.filter_by(ParentID=current_user.id).all()

    parent_id = current_user.id

    if request.method == 'POST':
        # Handle the deletion of a student
        student_id = request.form['student_id']
        student_to_delete = Student.query.get(student_id)

        if student_to_delete and student_to_delete.ParentID == parent_id:
            # Delete the student from the database
            db.session.delete(student_to_delete)
            db.session.commit()
            flash('Student deleted successfully!', 'success')
        else:
            flash('Student not found or not associated with the current parent!', 'danger')

        return redirect(url_for('my_students'))  # Make sure this matches the function name

    return render_template('my_students.html', students=students, parent_id=parent_id)  # Pass 'students' instead of 'children'

#checkpointwraps
def school_authority_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'School Authority':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

#checkpoint view
@app.route('/checkpoints', methods=['GET'])
@school_authority_required
def checkpoints():
    checkpoints = CheckPoint.query.filter_by(AuthorityID=current_user.id).all()
    return render_template('checkpoints.html', checkpoints=checkpoints)

#checkpoint add
@app.route('/checkpoints/add', methods=['GET', 'POST'])
@school_authority_required
def add_checkpoint() -> str:
    if request.method == 'POST':
        location: str = request.form.get('location')
        end_time_str: str = request.form.get('end_time')

        if location and end_time_str:
            try:
                # Convert the string 'end_time' to a Python datetime object
                end_time: datetime = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M")

                sast_tz = pytz.timezone('Africa/Johannesburg')
                end_time_sast = sast_tz.localize(end_time)

                # Create a new CheckPoint and save it to the database
                new_checkpoint = CheckPoint(Checkpoint_Location=location, Checkpoint_EndTime=end_time_sast, AuthorityID=current_user.id, IsCurrent=True)
                db.session.add(new_checkpoint)
                db.session.commit()

                # Set IsCurrent to False for all other checkpoints associated with this authority
                CheckPoint.query.filter_by(AuthorityID=current_user.id).update({'IsCurrent': False})

                flash('Checkpoint added successfully!', 'success')
                return redirect(url_for('checkpoints'))
            except ValueError as e:
                # Flash an error message if the date conversion fails
                flash(f'Invalid date/time format: {e}', 'error')
        else:
            # Flash an error message if the form data is incomplete
            flash('Please fill in all fields.', 'error')

    # Render the template without time options
    return render_template('add_checkpoint.html')

#checkpoint delete
@app.route('/checkpoints/delete/<int:checkpoint_id>', methods=['POST'])
@school_authority_required
def delete_checkpoint(checkpoint_id):
    checkpoint = CheckPoint.query.get_or_404(checkpoint_id)
    db.session.delete(checkpoint)
    db.session.commit()
    flash('Checkpoint deleted successfully!', 'success')
    return redirect(url_for('checkpoints'))

#parent Manage
@app.route('/parents')
def view_parents():
    parents = Parent.query.all()  # Fetch all parents
    return render_template('view_parents.html', parents=parents)
      
# student-parent view
@app.route('/parents/<int:parent_id>/students')
def view_students(parent_id):
    parent = Parent.query.get(parent_id)  # Fetch parent by ID
    if parent:
        students = Student.query.filter_by(ParentID=parent.ParentID).all()
        #students = Student.query.filter_by(ParentID=parent_id).all()

        return render_template('view_students.html', parent=parent, students=students, parent_id=parent_id)
    else:
        flash("Parent not found", "error")
        return redirect(url_for('view_parents'))
    
#del students
@app.route('/students/<int:student_id>/delete', methods=['POST'])
def delete_student(student_id):
    student = Student.query.get(student_id)  # Fetch student by ID
    if student:
        parent_id = student.ParentID
        db.session.delete(student)  # Deleting the student will also remove related records due to cascade
        db.session.commit()
        flash(f'Student deleted successfully', 'success')
    else:
        flash(f'Student not found', 'error')

    return redirect(url_for('view_students', parent_id=parent_id))

# Delete Account
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = User.query.filter_by(id=current_user.id).first()

    if user:
        # If you need to remove related data from other tables, do it here
        db.session.delete(user)
        db.session.commit()
        flash('Your account has been deleted.')
        return redirect(url_for('home'))
    
    flash('Account not found.')
    return redirect(url_for('home'))

#scans view   
@app.route('/scan')
@login_required
def scan_checkpoints():
    # Use current_user.id to fetch the checkpoints if that's how AuthorityID is stored
    checkpoints = CheckPoint.query.filter_by(AuthorityID=current_user.id, IsCurrent=True).all()
    
    # Render the checkpoints to the template
    return render_template('scan.html', checkpoints=checkpoints)

#scan qr code
@app.route('/qr_code_scan/<int:checkpoint_id>')
@login_required
def qr_code_scan(checkpoint_id):
    checkpoint = CheckPoint.query.get_or_404(checkpoint_id)
    return render_template('qr_code_scan.html', checkpoint=checkpoint)

#scan records
@app.route('/scan_record/<int:checkpoint_id>')
@login_required
def scan_record(checkpoint_id):
    checkpoint = CheckPoint.query.get_or_404(checkpoint_id)
    
    # get both ScanRecord and the associated Student
    scan_records = db.session.query(ScanRecord, Student) \
    .join(Student, ScanRecord.StudentID == Student.StudentID) \
    .filter(ScanRecord.CheckpointID == checkpoint_id) \
    .all()
    
    return render_template('scan_record.html', checkpoint=checkpoint, scan_records=scan_records)

#scan logic
@app.route('/api/scan', methods=['POST'])
@login_required
def process_scan():
    data = request.json
    qr_code = data['qrCode'] 
    checkpoint_id = data['checkpointID']

    # Split the QR code data
    try:
        student_id_no, student_name, student_surname = qr_code.split('|')
    except ValueError:
        return jsonify({"success": False, "message": "Invalid QR Code format"}), 400

    # Check if student exists based on Student ID Number
    student = Student.query.filter_by(Student_ID_NO=student_id_no).first()

    if student:
        # Check if the student has already scanned at this checkpoint
        existing_scan = ScanRecord.query.filter_by(StudentID=student.StudentID, CheckpointID=checkpoint_id).first()
        if not existing_scan:
            # Save new scan record
            new_scan = ScanRecord(
                Scan_Status="Captured",
                StudentID=student.StudentID,
                CheckpointID=checkpoint_id
            )
            db.session.add(new_scan)
            db.session.commit()
            return jsonify({"success": True}), 200
        else:
            return jsonify({"success": False, "message": "Student already scanned"}), 400
    else:
        return jsonify({"success": False, "message": "Invalid QR Code"}), 400

#NOTIFICATIONS JOB
def send_notifications(app):
    # Create an application context
    with app.app_context():
        # Get the current time in SAST
        sast_tz = pytz.timezone('Africa/Johannesburg')
        current_time_sast = datetime.now(sast_tz)

        # Query for checkpoints that have ended (Checkpoint_EndTime <= current time)
        # Calculate the time window
        time_window = current_time_sast - timedelta(minutes=2)

        # Query for checkpoints that ended in the specified window
        ended_checkpoints = CheckPoint.query.filter(
            CheckPoint.Checkpoint_EndTime <= current_time_sast,
            CheckPoint.Checkpoint_EndTime >= time_window
        ).limit(100).all()

        # Query for available checkpoints (Checkpoint_EndTime >= current time)
        ava = CheckPoint.query.filter(CheckPoint.Checkpoint_EndTime >= current_time_sast).limit(100).all()

        logger.info(f"Found {len(ava)} available checkpoints")
        logger.info(f"Found {len(ended_checkpoints)} ended checkpoints")

        for checkpoint in ended_checkpoints:
            students_without_scans = Student.query.join(Parent).filter(
                Student.ParentID == Parent.ParentID
            ).outerjoin(ScanRecord, (ScanRecord.StudentID == Student.StudentID) & 
                       (ScanRecord.CheckpointID == checkpoint.CheckpointID)).filter(
                ScanRecord.ScanID == None
            ).all()

            logger.info(f"Found {len(students_without_scans)} students without scans for checkpoint {checkpoint.Checkpoint_Location}")

            for student in students_without_scans:
                # Check if a record for the student already exists
                existing_scan = ScanRecord.query.filter_by(
                    StudentID=student.StudentID,
                    CheckpointID=checkpoint.CheckpointID,
                    Scan_Time=checkpoint.Checkpoint_EndTime
                ).first()

                if existing_scan is None:
                    # Create a new ScanRecord for the student who did not scan
                    new_scan = ScanRecord(
                        Scan_Time=checkpoint.Checkpoint_EndTime,
                        Scan_Status="Uncaptured",
                        StudentID=student.StudentID,
                        CheckpointID=checkpoint.CheckpointID
                    )
                    db.session.add(new_scan)
                    db.session.commit()

                    parent = db.session.get(Parent, student.ParentID)
                    parent_email = parent.Parent_EmailAddress

                    # Create the email content using the email template
                    body = render_template(
                        'email_template.html',
                        parent_name=parent.Parent_Name,
                        student_name=student.Student_Name,
                        checkpoint_location=checkpoint.Checkpoint_Location
                    )

                    # Prepare the email message
                    msg = MIMEMultipart()
                    msg['From'] = SENDER_EMAIL
                    msg['To'] = parent_email
                    msg['Subject'] = "Notification: Student didn't scan at checkpoint"
                    msg.attach(MIMEText(body, 'html'))

                    # Send the email using SMTP
                    try:
                        with smtplib.SMTP('smtp.sendgrid.net', 587) as server:
                            server.starttls()  # Enable TLS
                            server.login(SENDGRID_USERNAME, SENDGRID_PASSWORD)
                            server.sendmail(SENDER_EMAIL, parent_email, msg.as_string())

                        logger.info(f"Sent notification to {parent_email}")

                        # Create a new notification record in the database
                        notification = Notification(
                            Notification_SendTime=datetime.now(pytz.UTC),
                            Notification_Message=f"Student {student.Student_Name} did not scan at checkpoint {checkpoint.Checkpoint_Location}",
                            ParentID=parent.ParentID,
                            ScanID=new_scan.ScanID
                        )
                        db.session.add(notification)
                        db.session.commit()

                    except Exception as e:
                        logger.error(f"Failed to send notification to {parent_email}: {str(e)}")
                else:
                    logger.info(f"Skipping student {student.StudentID} as a record already exists for checkpoint {checkpoint.CheckpointID}")
# Add job to the scheduler to run `send_notifications` every minute
scheduler = BackgroundScheduler()
scheduler.add_job(send_notifications, args=(app,), trigger=IntervalTrigger(minutes=1), id='send_notifications')
scheduler.start()

def parent_required(p):
    @wraps(p)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Parent':
            flash("Access denied! Only parents can view this page.", "danger")
            return redirect(url_for('login'))
        return p(*args, **kwargs)
    return decorated_function

@app.route('/parent/notifications')
@login_required
@parent_required
def notifications():
    # Get the current logged-in parent
    parent = Parent.query.get(current_user.id)
    
    # Fetching 'captured' students (those who scanned) associated with this parent, ordered by scan time (descending)
    scanned_students = ScanRecord.query.filter_by(Scan_Status='Captured') \
                                       .join(Student) \
                                       .filter(Student.ParentID == parent.ParentID) \
                                       .order_by(ScanRecord.Scan_Time.desc()) \
                                       .all()

    # Fetching 'uncaptured' students (those who missed the scan) associated with this parent
    not_scanned_students = ScanRecord.query.filter_by(Scan_Status='Uncaptured') \
                                           .join(Student) \
                                           .filter(Student.ParentID == parent.ParentID) \
                                           .all()

    # Preparing data structures
    scanned_notifications = []
    not_scanned_notifications = []

    # Time zone for sorting by Scan_Time in South African Standard Time (SAST)
    sast = pytz.timezone('Africa/Johannesburg')

    # Processing scanned students and fetching their notifications
    for scan_record in scanned_students:
        student = scan_record.student  # Assuming there's a relationship from ScanRecord to Student
        # Get notifications for this scan record
        notifications = Notification.query.filter_by(ScanID=scan_record.ScanID).all()

        # Converting scan time to SAST
        scan_time_sast = scan_record.Scan_Time.astimezone(sast)

        scanned_notifications.append({
            'student': student,
            'scan_time': scan_time_sast,  # Scan time in SAST
            'notifications': notifications
        })

    # Processing unscanned students and fetching their notifications
    for scan_record in not_scanned_students:
        student = scan_record.student  # Assuming there's a relationship from ScanRecord to Student
        # Get notifications related to unscanned students
        notifications = Notification.query.filter_by(ScanID=scan_record.ScanID).all()

        not_scanned_notifications.append({
            'student': student,
            'notifications': notifications
        })

    # Rendering the HTML template
    return render_template('notifications.html',
                           scanned_notifications=scanned_notifications,
                           not_scanned_notifications=not_scanned_notifications,
                           parent=parent)

#pdf download
@app.route('/download_pdf/<int:checkpoint_id>')
def download_pdf(checkpoint_id):
    # Get the checkpoint and scan records (replace this with your actual query)
    checkpoint = CheckPoint.query.get_or_404(checkpoint_id)
    scan_records = db.session.query(ScanRecord, Student) \
        .join(Student, ScanRecord.StudentID == Student.StudentID) \
        .filter(ScanRecord.CheckpointID == checkpoint_id) \
        .distinct(Student.StudentID) \
        .all()

    # Render the template to a string
    rendered = render_template('scan_record.html', checkpoint=checkpoint, scan_records=scan_records)

    # Create PDF from the rendered HTML
    pdf = pdfkit.from_string(rendered, False)

    # Create a response with the PDF file
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_records_{checkpoint.Checkpoint_Location}.pdf'

    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)