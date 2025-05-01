
import pyotp
from functools import wraps
from flask import flash, redirect, url_for, session
from database import User, Session as DBSession
from config import Config

def requires_roles(*required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            db_session = DBSession()
            user = db_session.query(User).get(session['user_id'])
            
            if not any(role in user.roles for role in required_roles):
                flash('Permission denied', 'danger')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_totp_uri(user):
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db_session = DBSession()
        db_session.add(user)
        db_session.commit()
    
    return pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email,
        issuer_name=Config.MFA_ISSUER
    )