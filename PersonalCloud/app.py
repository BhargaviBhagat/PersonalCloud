# app.py
import os
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
import qrcode
from flask import send_file, session, abort
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_session import Session
from cryptography.fernet import Fernet
import pyotp
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from database import User, Bucket, File, SharedLink, FileVersion, Session as DBSession, init_db
from config import Config
from encryption import generate_key, encrypt_file, decrypt_file
from sqlalchemy import text


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config.from_object(Config)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
Session(app)
app.config.from_object(Config)



try:
    with app.app_context():
        init_db()
except Exception as e:
    logger.error(f"Failed to initialize database: {str(e)}")
    raise

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if 'user_id' not in session:
                flash('Please log in to access this page', 'warning')
                return redirect(url_for('login', next=request.url))
            
            db_session = DBSession()
            user = db_session.query(User).get(session['user_id'])
            if not user or not user.is_active:
                session.clear()
                flash('Session expired', 'warning')
                return redirect(url_for('login'))
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Login required error: {str(e)}")
            flash('An error occurred during authentication', 'danger')
            return redirect(url_for('login'))
        finally:
            db_session.close()
    return decorated_function

def generate_totp_uri(user):
    try:
        if not user.totp_secret:
            user.totp_secret = pyotp.random_base32()
            db_session = DBSession()
            db_session.add(user)
            db_session.commit()
        
        totp = pyotp.TOTP(user.totp_secret, issuer=app.config['MFA_ISSUER'])
        return totp.provisioning_uri(name=user.email, issuer_name=app.config['MFA_ISSUER'])
    except Exception as e:
        logger.error(f"TOTP generation error: {str(e)}")
        raise

@app.route('/')
def home():
    try:
        return render_template('home.html')
    except Exception as e:
        logger.error(f"Home page error: {str(e)}")
        abort(500)

@app.route('/login', methods=['GET', 'POST'])
def login():
    db_session = None
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            totp_code = request.form.get('totp_code')
            
            if not username or not password:
                flash('Username and password are required', 'danger')
                return redirect(url_for('login'))
            
            db_session = DBSession()
            user = db_session.query(User).filter_by(username=username).first()
            
            if user and bcrypt.check_password_hash(user.password, password):
                if user.totp_secret:
                    if not totp_code or not pyotp.TOTP(user.totp_secret).verify(totp_code):
                        flash('Invalid 2FA code', 'danger')
                        return redirect(url_for('login'))
                
                session['user_id'] = user.id
                user.last_login = datetime.utcnow()
                db_session.commit()
                
                next_page = request.args.get('next') or url_for('dashboard')
                return redirect(next_page)
            
            flash('Invalid username or password', 'danger')
        
        return render_template('login.html')
    except SQLAlchemyError as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Database error during login: {str(e)}")
        flash('An error occurred during login', 'danger')
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        flash('An error occurred during login', 'danger')
        return redirect(url_for('login'))
    finally:
        if db_session:
            db_session.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    db_session = None
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('register'))
            
            db_session = DBSession()
            
            try:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(
                    username=username,
                    email=email,
                    password=hashed_password,
                    is_active=True,
                    roles=['user']
                )
                db_session.add(new_user)
                db_session.commit()
                
                mfa_uri = generate_totp_uri(new_user)
                session['mfa_setup_uri'] = mfa_uri
                session['user_id'] = new_user.id
                
                return redirect(url_for('setup_mfa'))
                
            except IntegrityError:
                db_session.rollback()
                flash('Username or email already exists', 'danger')
        
        return render_template('register.html')
    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Registration error: {str(e)}")
        flash('An error occurred during registration', 'danger')
        return redirect(url_for('register'))
    finally:
        if db_session:
            db_session.close()

@app.route('/qr-code')
def qr_code():
    try:
        if 'mfa_setup_uri' not in session:
            abort(404)
        
        # Create QR code
        img = qrcode.make(session['mfa_setup_uri'])
        buf = BytesIO()
        img.save(buf)
        buf.seek(0)
        
        return send_file(buf, mimetype='image/png')
    except Exception as e:
        logger.error(f"QR code generation error: {str(e)}")
        abort(500)


@app.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    db_session = None
    try:
        if 'mfa_setup_uri' not in session:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            totp_code = request.form.get('totp_code')
            if not totp_code:
                flash('Verification code is required', 'danger')
                return redirect(url_for('setup_mfa'))
            
            db_session = DBSession()
            user = db_session.query(User).get(session['user_id'])
            
            if pyotp.TOTP(user.totp_secret).verify(totp_code):
                flash('2FA setup successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid verification code', 'danger')
        
        return render_template('setup_mfa.html', mfa_uri=session['mfa_setup_uri'])
    except Exception as e:
        logger.error(f"MFA setup error: {str(e)}")
        flash('An error occurred during MFA setup', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

@app.route('/dashboard')
@login_required
def dashboard():
    db_session = None
    try:
        db_session = DBSession()
        user = db_session.query(User).get(session['user_id'])
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
        
       
        buckets = db_session.query(Bucket).filter_by(user_id=user.id).all()
        files = db_session.query(File).join(Bucket).filter(Bucket.user_id == user.id).all()
        
        return render_template('dashboard.html',
                            user=user,
                            buckets=buckets,
                            files=files)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'danger')
        return redirect(url_for('login'))
    finally:
        if db_session:
            db_session.close()

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        bucket_id = request.form.get('bucket_id')
        encryption_password = request.form.get('password', '')
        
        
        db_session = DBSession()
        user = db_session.query(User).get(session['user_id'])
        bucket = db_session.query(Bucket).filter_by(id=bucket_id, user_id=user.id).first()
        
        if not bucket:
            flash('Invalid bucket', 'danger')
            return redirect(url_for('dashboard'))
        
        
        filename = secure_filename(file.filename)
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{secrets.token_hex(8)}_{filename}")
        file.save(temp_path)
        
        
        key, salt = generate_key(encryption_password)
        encrypted_path = encrypt_file(temp_path, key)
        
        
        new_file = File(
            bucket_id=bucket.id,
            filename=filename,
            encrypted_path=encrypted_path,
            salt=salt
        )
        db_session.add(new_file)
        db_session.commit()
        
        flash('File uploaded successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        if 'db_session' in locals():
            db_session.rollback()
        flash(f'Upload failed: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if 'db_session' in locals():
            db_session.close()
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    db_session = None
    try:
        db_session = DBSession()
        user = db_session.query(User).get(session['user_id'])
        file = db_session.query(File).filter_by(id=file_id).join(Bucket).filter(Bucket.user_id == user.id).first()
        
        if not file:
            flash('File not found or permission denied', 'danger')
            return redirect(url_for('dashboard'))
        
        try:
            return send_from_directory(
                directory=os.path.dirname(file.encrypted_path),
                path=os.path.basename(file.encrypted_path),
                as_attachment=True,
                download_name=file.filename
            )
        except Exception as e:
            logger.error(f"File download error: {str(e)}")
            raise
        
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

@app.route('/admin')
@login_required
def admin_panel():
    db_session = None
    try:
        db_session = DBSession()
        users = db_session.query(User).all()
        return render_template('admin.html', users=users)
    except Exception as e:
        logger.error(f"Admin panel error: {str(e)}")
        flash('Error loading admin panel', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

@app.route('/health')
def health():
    db_session = None
    try:
        db_session = DBSession()
        
        db_session.execute(text('SELECT 1'))
        return 'OK', 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return 'Service Unavailable', 503
    finally:
        if db_session:
            db_session.close()

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 Error: {str(e)}")
    return render_template('500.html'), 500

@app.route('/create_bucket', methods=['POST'])
@login_required
def create_bucket():
    db_session = None
    try:
        bucket_name = request.form.get('bucket_name')
        if not bucket_name:
            flash('Bucket name is required', 'danger')
            return redirect(url_for('dashboard'))
        
        db_session = DBSession()
        user = db_session.query(User).get(session['user_id'])
        
        new_bucket = Bucket(
            name=bucket_name,
            user_id=user.id,
            is_encrypted=True
        )
        db_session.add(new_bucket)
        db_session.commit()
        
        flash('Bucket created successfully!', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Bucket creation error: {str(e)}")
        flash('Error creating bucket', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()

@app.route('/share/<int:file_id>')
@login_required
def share(file_id):
    db_session = None
    try:
        db_session = DBSession()
        user = db_session.query(User).get(session['user_id'])
        file = db_session.query(File).filter_by(id=file_id).join(Bucket).filter(Bucket.user_id == user.id).first()
        
        if not file:
            flash('File not found or permission denied', 'danger')
            return redirect(url_for('dashboard'))
        
        # Create a shared link
        shared_link = SharedLink(
            file_id=file.id,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        db_session.add(shared_link)
        db_session.commit()
        
        flash(f'Share link created: {shared_link.token}', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Share error: {str(e)}")
        flash('Error creating share link', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        if db_session:
            db_session.close()
            
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=5000)
    except Exception as e:
        logger.error(f"Application startup failed: {str(e)}")
        raise