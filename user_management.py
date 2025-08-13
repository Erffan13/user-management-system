from flask import Flask, request, jsonify, render_template, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import re
import uuid
import logging
from email.mime.text import MIMEText

app = Flask(__name__)

# تنظیمات Flask
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['RESET_TOKEN_EXPIRY'] = 3600
app.config['SESSION_TYPE'] = 'filesystem'

# تنظیم لاگ‌گیری
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# تنظیم Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# مدل کاربر
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

# مدل توکن بازنشانی
class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)

# ایجاد پایگاه داده
with app.app_context():
    db.create_all()

# اعتبارسنجی
def validate_username(username):
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False, "Username must be 3-20 characters, alphanumeric or underscore"
    return True, ""

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    return True, ""

def validate_email(email):
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return False, "Invalid email format"
    return True, ""

# تابع تولید توکن JWT
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# تابع بررسی توکن
def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            logger.warning("Token missing in request")
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                logger.warning(f"User not found for token: {token}")
                return jsonify({'message': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token used")
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            logger.warning("Invalid token used")
            return jsonify({'message': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorator

# تابع بررسی نقش ادمین
def admin_required(f):
    def decorator(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            logger.warning(f"Unauthorized access attempt by {current_user.username}")
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return token_required(decorator)

# شبیه‌سازی ارسال ایمیل
def send_reset_email(email, token):
    msg = MIMEText(f'Reset your password using this link: http://localhost:5000/reset-password/{token}')
    msg['Subject'] = 'Password Reset Request'
    msg['From'] = 'no-reply@yourapp.com'
    msg['To'] = email
    print(f"Simulated email sent to {email}: {msg.as_string()}")
    logger.info(f"Password reset email sent to {email}")

# مسیرهای HTML
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/reset-password-request')
def reset_password_request_page():
    return render_template('reset_password_request.html')

@app.route('/reset-password/<token>')
def reset_password_page(token):
    return render_template('reset_password.html', token=token)

# مسیر ثبت‌نام
@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def register():
    data = request.form if request.form else request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    valid_username, username_error = validate_username(username)
    valid_password, password_error = validate_password(password)
    valid_email, email_error = validate_email(email)

    if not valid_username:
        logger.warning(f"Invalid username: {username}")
        return jsonify({'message': username_error}), 400
    if not valid_password:
        logger.warning(f"Invalid password for user: {username}")
        return jsonify({'message': password_error}), 400
    if not valid_email:
        logger.warning(f"Invalid email: {email}")
        return jsonify({'message': email_error}), 400

    if User.query.filter_by(username=username).first():
        logger.warning(f"Username already exists: {username}")
        return jsonify({'message': 'Username already exists'}), 400
    if User.query.filter_by(email=email).first():
        logger.warning(f"Email already exists: {email}")
        return jsonify({'message': 'Email already exists'}), 400

    password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, email=email, password_hash=password_hash, role='user')
    db.session.add(new_user)
    db.session.commit()
    logger.info(f"New user registered: {username}")

    return jsonify({'message': 'User registered successfully'}), 201

# مسیر ورود
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def login():
    data = request.form if request.form else request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        logger.warning(f"Failed login attempt for username: {username}")
        return jsonify({'message': 'Invalid credentials'}), 401

    token = generate_token(user.id)
    logger.info(f"User logged in: {username}")
    return jsonify({'token': token}), 200

# مسیر درخواست بازنشانی رمز
@app.route('/api/reset-password-request', methods=['POST'])
@limiter.limit("3 per hour")
@csrf.exempt
def reset_password_request():
    data = request.form if request.form else request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        logger.warning(f"Password reset requested for non-existent email: {email}")
        return jsonify({'message': 'Email not found'}), 404

    token = str(uuid.uuid4())
    expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=app.config['RESET_TOKEN_EXPIRY'])
    reset_token = ResetToken(token=token, user_id=user.id, expiry=expiry)
    db.session.add(reset_token)
    db.session.commit()

    send_reset_email(user.email, token)
    return jsonify({'message': 'Password reset link sent'}), 200

# مسیر بازنشانی رمز
@app.route('/api/reset-password/<token>', methods=['POST'])
@csrf.exempt
def reset_password(token):
    data = request.form if request.form else request.get_json()
    new_password = data.get('password')

    valid_password, password_error = validate_password(new_password)
    if not valid_password:
        logger.warning(f"Invalid password reset attempt: {password_error}")
        return jsonify({'message': password_error}), 400

    reset_token = ResetToken.query.filter_by(token=token).first()
    if not reset_token or reset_token.expiry < datetime.datetime.utcnow():
        logger.warning(f"Invalid or expired reset token: {token}")
        return jsonify({'message': 'Invalid or expired reset token'}), 400

    user = User.query.get(reset_token.user_id)
    user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.delete(reset_token)
    db.session.commit()
    logger.info(f"Password reset for user: {user.username}")

    return jsonify({'message': 'PasswordCompressor reset successfully'}), 200

# مسیر به‌روزرسانی پروفایل
@app.route('/api/profile', methods=['PUT'])
@token_required
@csrf.exempt
def update_profile(current_user):
    data = request.get_json()
    new_username = data.get('username')
    new_email = data.get('email')

    valid_username, username_error = validate_username(new_username)
    valid_email, email_error = validate_email(new_email)

    if not valid_username:
        logger.warning(f"Invalid username update: {username_error}")
        return jsonify({'message': username_error}), 400
    if not valid_email:
        logger.warning(f"Invalid email update: {email_error}")
        return jsonify({'message': email_error}), 400

    if new_username != current_user.username and User.query.filter_by(username=new_username).first():
        logger.warning(f"Username already exists: {new_username}")
        return jsonify({'message': 'Username already exists'}), 400
    if new_email != current_user.email and User.query.filter_by(email=new_email).first():
        logger.warning(f"Email already exists: {new_email}")
        return jsonify({'message': 'Email already exists'}), 400

    current_user.username = new_username
    current_user.email = new_email
    db.session.commit()
    logger.info(f"Profile updated for user: {current_user.username}")

    return jsonify({'message': 'Profile updated successfully'}), 200

# مسیر حذف حساب
@app.route('/api/profile', methods=['DELETE'])
@token_required
@csrf.exempt
def delete_account(current_user):
    logger.info(f"Account deleted: {current_user.username}")
    db.session.delete(current_user)
    db.session.commit()
    return jsonify({'message': 'Account deleted successfully'}), 200

# مسیر مشاهده پروفایل
@app.route('/api/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({'username': current_user.username, 'email': current_user.email, 'role': current_user.role}), 200

# مسیر مدیریت کاربران (فقط ادمین)
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users(current_user):
    users = User.query.all()
    return jsonify([{'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role} for user in users]), 200

# مسیر ارتقای نقش کاربر (فقط ادمین)
@app.route('/api/admin/users/<int:user_id>/promote', methods=['PUT'])
@admin_required
def promote_user(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        logger.warning(f"Attempt to promote non-existent user ID: {user_id}")
        return jsonify({'message': 'User not found'}), 404
    if user.role == 'admin':
        logger.warning(f"Attempt to promote already admin user: {user.username}")
        return jsonify({'message': 'User is already an admin'}), 400
    user.role = 'admin'
    db.session.commit()
    logger.info(f"User promoted to admin: {user.username}")
    return jsonify({'message': f'User {user.username} promoted to admin'}), 200

if __name__ == '__main__':
    app.run(debug=True)