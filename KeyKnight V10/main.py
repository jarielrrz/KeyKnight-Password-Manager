from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from datetime import datetime
import bcrypt
import secrets
import hashlib
import requests
import string
import random
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import os
from zxcvbn import zxcvbn  # Import zxcvbn for password strength estimation

# Function to generate a secret key
def generate_secret_key():
    return os.urandom(24)

app = Flask(__name__)

# Configuration for SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = generate_secret_key()  # Generate a secret key for flash messages

# Initialize the database
db = SQLAlchemy()
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

# Define the Password model
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    validity_duration = db.Column(db.Integer)  # New field to store validity duration in months
    last_generated = db.Column(db.DateTime)  # New field to store the last time password was generated
    strength = db.Column(db.Integer)  # Field to store password strength

    user = db.relationship('User', backref=db.backref('passwords', lazy=True))

    def __repr__(self):
        return f'<Password for {self.website}>'
    
# Define the FlaskMessage model
class FlaskMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(20), nullable=False)  # Category of the message, e.g., 'success', 'error', 'info'
    message = db.Column(db.Text, nullable=False)

    user = db.relationship('User', backref=db.backref('flask_messages', lazy=True))

    def __repr__(self):
        return f'<FlaskMessage {self.category}: {self.message}>'


def store_flashed_message(user_id, category, message):
    new_message = FlaskMessage(user_id=user_id, category=category, message=message)
    db.session.add(new_message)
    db.session.commit()


@app.context_processor
def inject_flashed_messages():
    if current_user.is_authenticated:
        flashed_messages = current_user.flask_messages
    else:
        flashed_messages = None
    return dict(flashed_messages=flashed_messages)



class SecureNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

    user = db.relationship('User', backref=db.backref('secure_notes', lazy=True))


@app.route('/save_secure_note', methods=['POST'])
@login_required
def save_secure_note():
    title = request.form['title']
    content = request.form['content']

    # Create a new secure note
    new_note = SecureNote(user_id=current_user.id, title=title, content=content)
    db.session.add(new_note)
    db.session.commit()

    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    store_flashed_message(current_user.id, 'success', f'Secure note saved successfully! as of {current_datetime}')
    return Response(status=204)



@app.route('/secure_notes')
@login_required
def secure_notes():
    # Retrieve the user's secure notes
    secure_notes = current_user.secure_notes

    return render_template('secure_notes.html', secure_notes=secure_notes)


# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    # This is a cache-busting parameter to the URL using the current timestamp
    cache_buster = int(datetime.now().timestamp())
    return render_template('index.html', cache_buster=cache_buster)




@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    # Check if the username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists!', 'error')
        return redirect(url_for('index')) 
    
    # Create a new user
    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Registration successful! Please log in.', 'success')
    return redirect(url_for('index'))  





@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Query the database for the user
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('password_manager', user_id=user.id))  
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('index')) 





@app.route('/password_health_info')
@login_required
def password_health_info():
    # Query the database to get the required information about passwords
    weak_passwords_count = Password.query.filter(Password.user_id == current_user.id, Password.strength < 3).count()
    reused_passwords_count = Password.query.filter(Password.user_id == current_user.id).group_by(Password.password).having(func.count() > 1).count()
    expiring_passwords_count = Password.query.filter(Password.user_id == current_user.id, Password.validity_duration <= 1).count()

    # Prepare the data to send back to the client
    data = {
        'weak_passwords_count': weak_passwords_count,
        'reused_passwords_count': reused_passwords_count,
        'expiring_passwords_count': expiring_passwords_count
    }

    return jsonify(data)




# Initialize the scheduler
scheduler = BackgroundScheduler()
scheduler.start()




# Function to send password health status notification
def send_password_health_notification():
    # Query the database to get the required information about passwords
    weak_passwords_count = Password.query.filter(Password.user_id == current_user.id, Password.strength < 3).count()
    reused_passwords_count = Password.query.filter(Password.user_id == current_user.id).group_by(Password.password).having(func.count() > 1).count()
    expiring_passwords_count = Password.query.filter(Password.user_id == current_user.id, Password.validity_duration <= 1).count()

    # Format current date and time
    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Prepare the notification message
    notification_message = f"HEALTH STATUS: You have {weak_passwords_count} weak passwords, {reused_passwords_count} reused passwords, and {expiring_passwords_count} expired passwords as of {current_datetime}! Please change these accordingly."

    # Store the notification message in the database
    store_flashed_message(current_user.id, 'info', notification_message)

# Schedule the function to run once a day at a specific time, such as midnight
scheduler.add_job(send_password_health_notification, trigger=CronTrigger(hour=0))


HIBP_API_URL = "https://api.pwnedpasswords.com/range/{}"
HIBP_API_KEY = "7bc06cf3857b4cdf89e3072926243a67"



def check_database_passwords(user_id):
    compromised_passwords = []
    user_passwords = Password.query.filter_by(user_id=user_id).all()
    for password_obj in user_passwords:
        hashed_password = hashlib.sha1(password_obj.password.encode()).hexdigest().upper()
        prefix = hashed_password[:5]
        suffix = hashed_password[5:]
        response = requests.get(HIBP_API_URL.format(prefix), verify=False)
        if response.status_code == 200:
            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                if suffix == hash_suffix:
                    compromised_passwords.append(password_obj.password)
                    break
    
    # Format current date and time
    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Prepare the message based on compromised passwords
    if compromised_passwords:
        message = f'{len(compromised_passwords)} compromised passwords were found as of {current_datetime}! Please take measures.'
        category = 'error'
    else:
        message = f'Hooray! None of your passwords were found in a data breach as of {current_datetime}.'
        category = 'success'
    
    # Store the message in the database
    store_flashed_message(user_id, category, message)
    
    return compromised_passwords



@app.route('/compromised_passwords')
@login_required
def compromised_passwords():
    # Check compromised passwords for the current user
    compromised_passwords = check_database_passwords(current_user.id)
    return render_template('compromised_passwords.html', compromised_passwords=compromised_passwords)

@app.route('/password_manager/<int:user_id>', methods=['GET', 'POST'])
@login_required
def password_manager(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        validity_duration = int(request.form.get('validity_duration', 0))  # Get validity duration
        
        # Use zxcvbn to estimate password strength
        password_info = zxcvbn(password)
        strength_score = password_info['score']
        
        # Create a new password entry
        new_password = Password(user_id=user.id, website=website, username=username, password=password, validity_duration=validity_duration, strength=strength_score)
        db.session.add(new_password)
        db.session.commit()

        # Prepare message based on password strength
        if strength_score >= 3:
            message = f"Password for {website} added on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}! This password has a strength score of {strength_score} and is valid for {validity_duration} months. Hooyah!"
            category = 'success'
        else:
            message = f"Password for {website} added on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}! This password is weak. Please consider changing it for better security."
            category = 'warning'
        
        # Store the message in the database
        store_flashed_message(user_id, category, message)
        
        # Redirect to prevent form resubmission on refresh
        return redirect(url_for('password_manager', user_id=user.id))
    
    # Retrieve the passwords for the user
    passwords = user.passwords
    
    # Sort the passwords based on expiration date
    sorted_expiration = sorted(passwords, key=lambda x: x.validity_duration if x.validity_duration is not None else float('inf'))
    sorted_strength = sorted(passwords, key=lambda x: x.strength if x.strength is not None else float('inf'))
    
    # Render the template with sorted and color-coded passwords
    return render_template('password_manager.html', user=user, sorted_expiration=sorted_expiration, sorted_strength=sorted_strength)

@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    password = Password.query.get_or_404(password_id)
    
    if request.method == 'POST':
        # Update the password details
        password.website = request.form['website']
        password.username = request.form['username']
        password.password = request.form['password']
        password.validity_duration = int(request.form.get('validity_duration', 0))  # Update validity duration
        
        # Use zxcvbn to estimate password strength
        password_info = zxcvbn(password.password)
        password.strength = password_info['score']
        strength_score = password_info['score']

        db.session.commit()

        # Prepare message based on password strength
        if strength_score >= 3:
            # Store a success message in the database
            message = f'Password for {password.website} was updated successfully on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, and has a strength score of {strength_score} and a validity of {password.validity_duration} MONTHS! Let\'s go!'
            category = 'success'
        else:
            # Store a warning message for weak passwords in the database
            message = f'Password for {password.website} was updated successfully on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, and has a strength score of {strength_score}. Please consider a change.'
            category = 'warning'

        # Store the message in the database
        store_flashed_message(password.user_id, category, message)

        return redirect(url_for('password_manager', user_id=password.user_id))
    
    return render_template('edit_password.html', password=password)


@app.route('/delete_password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def delete_password(password_id):
    password = Password.query.get_or_404(password_id)
    user_id = password.user_id
    
    # Prepare message indicating password deletion
    message = f"Password for {password.website} was deleted on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    category = 'info'
    
    # Store the message in the database
    store_flashed_message(password.user_id, category, message)

    db.session.delete(password)
    db.session.commit()
    
    return redirect(url_for('password_manager', user_id=user_id))



@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        user_id = current_user.id
        logout_user()
        session.clear() 
        logout_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f'You have been logged out at {logout_time}.'
        category = 'success'
    else:
        user_id = None
        logout_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f'You have been logged out at {logout_time}.'
        category = 'success'

    # Store the message in the database
    store_flashed_message(user_id, category, message)

    return redirect(url_for('index'))



if __name__ == '__main__':
    with app.app_context():
        # Create the database tables
        db.create_all()

        # Initialize the scheduler
        scheduler = BackgroundScheduler()
        scheduler.start()
    



    # Run the Flask app
    app.run(debug=True, port=5004)
