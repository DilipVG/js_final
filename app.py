from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.form.upload import FileUploadField
import os
from twilio.rest import Client
import pyotp


app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/database_name'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:SaiPrasanth@localhost:5432/js'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure random key in a real application

app.config['UPLOADED_FILES_DEST'] = 'uploads/'
app.config['UPLOADED_FILES_URL'] = 'uploads/'


account_sid = 'ACf975f87e46327fe6e049777b6f31a72d'
auth_token = '563c14dd9bd9abf405d5ff88e5d8f5fc'
twilio_phone_number = '+19082900976'

client = Client(account_sid, auth_token)

otp_secret = pyotp.random_base32()
totp = pyotp.TOTP(otp_secret)

db = SQLAlchemy(app)
migrate = Migrate(app , db)
# db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

admin = Admin(app)

#DATABASE MODELS

class users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement = True)
    full_name = db.Column(db.Text, nullable = False)
    mobile = db.Column(db.Text, nullable = False, unique=True)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=True, unique=True)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), default=None)
    address = db.Column(db.Text, default = None)
    is_admin = db.Column(db.Boolean, default=False)
    policies = db.relationship('Policy', backref='users', lazy=True)

    def __repr__(self):
        return f'{self.full_name}'


class Policy(db.Model):
    policy_id = db.Column(db.Integer, primary_key=True, autoincrement = True)
    category = db.Column(db.String(255), nullable=False)
    policy_type = db.Column(db.String(255), nullable= False)
    insurance_company = db.Column(db.String(255), nullable=False)
    policy_name = db.Column(db.String(255), nullable = False)
    policy_no = db.Column(db.String(255), nullable= False)
    due_date = db.Column(db.Date, nullable=False)
    emi_amount = db.Column(db.Integer, nullable=False)
    policy_doc = db.Column(db.String, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable = False)
    # users = db.relationship( 'users' , backref='Policy')

    def __repr__(self):
        return f'<Policy {self.policy_no}>'

class MotorInsurance(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    motor_type = db.Column(db.Text, nullable=False)
    mobile = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<MotorInsurance {self.name}>'
class HealthInsurance(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    mobile = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    dob = db.Column(db.Date, nullable=True)
    age = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<HealthInsurance {self.name}>'   
class TravelInsurance(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    mobile = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False)
    travelling_to = db.Column(db.Text, nullable=False)
    from_date = db.Column(db.Date, nullable=False)
    to_date = db.Column(db.Date, nullable=False)
    days_count = db.Column(db.Integer, nullable=True)
    passenger_count = db.Column(db.Integer, nullable=False)

    def __rep__(self):
        return f'<TravelInsurance {self.name}>'
class WorkmenInsurance(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    mobile = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=True)
    city = db.Column(db.Text, nullable = False)
    company_name = db.Column(db.Text, nullable = False)

    def __repr__(self):
        return f'<WorkmenInsurance {self.name}>'
class PropertyInsurance(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.Text, nullable=False)
    mobile = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=True)
    city = db.Column(db.Text, nullable = False)
    
    def __repr__(self):
        return f'<PropertyInsurance {self.name}>'
class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement = True)
    customer_name = db.Column(db.Text, nullable=False)
    mobile = db.Column(db.Text, nullable=False)
    insurance_type = db.Column(db.Text)
    company_name = db.Column(db.Text)
    policy_np = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<Claim {self.policy_no}>'
class Appointments(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement = True)
    customer_name = db.Column(db.Text, nullable=False)
    dob = db.Column(db.Date, nullable=False)
    age = db.Column(db.Integer)
    mobile = db.Column(db.Text, nullable=False)
    updates = db.Column(db.Boolean, default = False, nullable=False)
    email = db.Column(db.Text)
    appointment = db.Column(db.Date, nullable=False)

    def __repr__(self):
        return f'<Appointment {self.customer_name}>'


@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))

class AdminModelView(ModelView):
    column_exclude_list = ['password']

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    
class UserAdminView(AdminModelView):
    column_list = ['id', 'full_name','mobile', 'email', 'dob', 'gender', 'address', 'is_admin', 'policies']


class PolicyAdminView(AdminModelView):
    can_create = True
    can_edit = True
    can_delete = True
    can_export = True
    form_columns = ('category', 'policy_type', 'insurance_company', 'policy_name', 'policy_no', 'due_date', 'emi_amount', 'policy_doc', 'users')

    form_extra_fields = {
        'policy_doc': FileUploadField('Policy Document', base_path='uploads/')
    }

    def on_model_change(self, form, model, is_created):
        if form.policy_doc._value:
            model.policy_doc = form.policy_doc.data.filename


admin.add_view(UserAdminView(users, db.session, name= 'My Customers'))
admin.add_view(PolicyAdminView(Policy, db.session, name='Policies'))

admin.add_view(AdminModelView(Appointments, db.session, name='My Appointments'))
admin.add_view(AdminModelView(Claim, db.session, name='Claims'))

admin.add_view(AdminModelView(HealthInsurance, db.session, category="Interests"))
admin.add_view(AdminModelView(MotorInsurance, db.session, category="Interests"))
admin.add_view(AdminModelView(TravelInsurance, db.session, category="Interests"))
admin.add_view(AdminModelView(WorkmenInsurance, db.session, category="Interests"))
admin.add_view(AdminModelView(PropertyInsurance, db.session, category="Interests"))

# ROUTING CODE FOR VIEWS

@app.route("/")
def home():
    if request.method == 'POST':
        customer_name = request.form['username']
        dob = request.form['dob']
        age = request.form['age']
        mobile = request.form['mobile']
        updates = request.form.get('updates') == "True"
        email = request.form['email']
        appointment = request.form['appointment_date']
        try:

            new_appointment = Appointments(
                customer_name = customer_name,
                dob = dob,
                age = age,
                mobile = mobile,
                updates = updates,
                email = email,
                appointment = appointment)
            db.session.add(new_appointment)
            db.session.commit()

            flash('User details are saved successfully', 'success')
        except Exception as e:
            flash('User Details are not saved', 'error')
        return redirect(url_for('home'))
    return render_template('home.html')

@app.route('/motor', methods = ['GET', 'POST'])
def motor_page():
    if request.method == 'POST':
        full_name = request.form['username']
        mobile = request.form['mobile']
        email = request.form['email']
        motor_type = request.form.get('motor-type')
        
        motor_interest = MotorInsurance(name = full_name, email = email, motor_type = motor_type, mobile = mobile)
        
        db.session.add(motor_interest)
        db.session.commit()
        
        flash("Your interest has been saved!", 'success')
        return redirect(url_for('motor_page'))
    
    return render_template('motor.html')



@app.route('/travel', methods = ['GET', 'POST'])
def travel_page():
    if request.method == 'POST':
        name = request.form['username']
        mobile = request.form['mobile']
        email = request.form['email']
        travelling_to = request.form['countries']
        from_date = request.form['departure_date']
        to_date = request.form['return_date']
        passenger_count = request.form['people']

        new_travel_interest = TravelInsurance(name = name,
                                              mobile = mobile,
                                              email = email,
                                              travelling_to = travelling_to,
                                              from_date = from_date,
                                              to_date = to_date,
                                              passenger_count = passenger_count)
        db.session.add(new_travel_interest)
        db.session.commit()

        flash("Your interest has been saved!", 'success')
        return redirect(url_for('travel_page'))

    return render_template('travel.html')


@app.route('/property', methods = ['GET', 'POST'])
def property_page():
    if request.method == 'POST':
        name = request.form['username']
        mobile = request.form['mobile']
        email = request.form['email']
        city = request.form['city']

        new_property_interest = PropertyInsurance(
            name = name,
            mobile = mobile,
            email = email,
            city = city
        )
        db.session.add(new_property_interest)
        db.session.commit()

        flash("Your interest has been saved!", 'success')
        return redirect(url_for('property_page'))

    return render_template('property.html')




@app.route('/workmen', methods = ['GET', 'POST'])
def workmen_page():
    if request.method == 'POST':
        name = request.form['username']
        mobile = request.form['mobile']
        email = request.form['email']
        company_name = request.form['company']
        city = request.form['city']

        new_workmen_interest = WorkmenInsurance(
            name = name,
            mobile = mobile,
            email = email,
            company_name = company_name,
            city = city
        )
        db.session.add(new_workmen_interest)
        db.session.commit()

        flash("Your interest has been saved!", 'success')
        return redirect(url_for('workmen_page'))

    return render_template('workmen.html')


@app.route('/health', methods = ['GET', 'POST'])
def health_page():
    if request.method == 'POST':
        name = request.form['username']
        mobile = request.form['mobile']
        email = request.form['email']
        age = request.form['age']

        new_health_interest = HealthInsurance(name=name,
                                              mobile = mobile,
                                              email = email,
                                              age = age)
        db.session.add(new_health_interest)
        db.session.commit()

        flash("Your interest has been saved!", 'success')
        return render_template('health.html')

    return render_template('health.html')



# Saving Appointment Requests
@app.route('/appointments', methods=['GET', 'POST'])
def appointments(): 
    if request.method == 'POST':
        customer_name = request.form['username']
        dob = request.form['dob']
        age = request.form['age']
        mobile = request.form['mobile']
        updates = request.form.get('updates') == "True"
        email = request.form['email']
        appointment = request.form['appointment_date']

        new_appointment = Appointments(
            customer_name = customer_name,
            dob = dob,
            age = age,
            mobile = mobile,
            updates = updates,
            email = email,
            appointment = appointment)
        db.session.add(new_appointment)
        db.session.commit()
        flash("Our team will contact you shortly!", 'success')

        return render_template('home.html', success_message=True)    
    # all_appointments = Appointments.query.all()
    return render_template('home.html')



@app.route("/signup", methods=['GET', 'POST'])
def signup():
    print("request type method:", request.method)
    if request.method == 'POST':
        print("request type method:", request.method)
        username = request.form['username']
        password = request.form['password']
        mobile = request.form['mobile']
        email = request.form['email']
        dob = request.form['dob']

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = users(full_name=username ,mobile = mobile, password=hashed_password, dob = dob, email = email)

        db.session.add(new_user)
        db.session.commit()

        # flash("Sign up Successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        mobile = request.form['mobile']
        password = request.form['password']

        user = users.query.filter_by(mobile=mobile).first()
        print(password)
        print(check_password_hash(user.password, password))
        if user and check_password_hash(user.password, password):
            login_user(user)
            # flash("Login Successful!", 'success')
            return redirect(url_for('dashboard'))
        else:
            # flash('Login failed. Please check your username and password.', 'error')
            return "Login failed"

    return render_template('login.html')


@app.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
            
    user_policies = Policy.query.filter_by(user_id = current_user.id).all()
    user = users.query.filter_by(id = current_user.id).first()
    if request.method == 'POST':
        print(request.form)
        username = request.form['username']
        mobile = request.form['mobile']
        email = request.form['email']
        dob = request.form['dob']
        gender = request.form['gender']
        address = request.form['address']

        user.full_name = username
        user.mobile = mobile
        user.email = email
        user.dob = dob
        user.gender = gender
        user.address = address
        db.session.commit()

        print(user.address)

    return render_template('dashboard.html', user_policies = user_policies, user = user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    # flash('Logout successful!', 'success')
    return redirect(url_for('home'))

# Saving Policy Claim Requests
@app.route('/claims', methods=['GET','POST'])
def claims():
    if request.method == 'POST':
        customer_name = request.form['customer_name']
        mobile = request.form['mobile']
        insurance_type = request.form['insurance_type']
        company_name = request.form['company_name']
        policy_no = request.form['policy_no']

        new_claim = Claim(customer_name = customer_name, mobile = mobile, insurance_type = insurance_type, company_name = company_name, policy_np = policy_no)

        db.session.add(new_claim)
        db.session.commit()

        return render_template('claim-success.html')

    return render_template('claims.html')


@app.route('/track', methods=['GET', 'POST'])
def track():
    if request.method == 'POST':
        insurance_type = request.form['insurance_type']
        company_name = request.form['company_name']
        policy_no = request.form['policy_no']

        policy_details = Policy.query.filter_by(policy_no = policy_no).first()
        user = users.query.filter_by(id = policy_details.user_id).first()
        # print(user.full_name)
        return render_template('track-details.html', policy_details = policy_details, username = user.full_name)

    return render_template('track.html')

@app.route('/download', methods=['GET','POST'])
def download():
    if request.method == 'POST':
        policy_no = request.form['policy_no']
        policy = Policy.query.filter_by(policy_no = policy_no).first()
        filename = policy.policy_doc
        return send_file(os.path.join(app.config['UPLOADED_FILES_DEST'], filename), as_attachment=True)
    return render_template('download_policy.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin.html', user=current_user)

# PASSWORD RESET
@app.route('/reset_password_request',methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        mobile = request.form['mobile']
        # send OTP
        
        otp_code = totp.now()

        # Save OTP to Database
        
        # new_otp = otp_db(mobile = mobile, otp = otp_code)
        # db.session.add(new_otp)
        # db.session.commit()

        # Send OTP via Twilio SMS
        message_body = f'Your OTP is: {otp_code}'
        message = client.messages.create(
            body=message_body,
            from_=twilio_phone_number,
            to=mobile
        )

        # Print the message SID to confirm the message was sent
        print(f'Message SID: {message.sid}')

        mobile = request.form['mobile']
        return redirect(url_for('verify_otp', mobile=mobile))
    return render_template('reset_password_request.html')

@app.route('/verify_otp/<mobile>', methods=['GET', 'POST'])
def verify_otp(mobile):
    if request.method == 'POST':
        # IF OTP's match, send them to password input page
        # mobile = request.form['mobile']
        user_otp = request.form['otp']
        if totp.verify(user_otp):
            return redirect(url_for('password_change', mobile=mobile))
        else:
            return render_template('verify_otp.html', mobile=mobile, message = 'Invalid OTP')
    return render_template('verify_otp.html', mobile=mobile)

@app.route('/password_change/<mobile>', methods=['GET', 'POST'])
def password_change(mobile):
    if request.method == 'POST':
        # Update Database with the new password for the user
        mobile = extract_mobile_number(mobile)
        user = users.query.filter_by(mobile = mobile).first()
        new_password = request.form['pass1']

        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.password = hashed_password

        db.session.commit()


        return redirect(url_for('login'))
    return render_template('password_change.html', mobile=mobile)

def extract_mobile_number(full_number):
    # Remove any non-digit characters
    numeric_part = ''.join(filter(str.isdigit, full_number))

    # Keep only the last 10 digits
    mobile_number = numeric_part[-10:]

    return mobile_number

def create_tables():
    with app.app_context():
        db.create_all()


if __name__ == "__main__":
    # db.create_all()
    create_tables()
    app.run(debug=True)