import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import psycopg2
from time import sleep
from datetime import timedelta

load_dotenv()

class Config:
    
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "PersonalCloud")
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "root")
    
    
    SECRET_KEY = os.getenv("SECRET_KEY", Fernet.generate_key().decode())
    SQLALCHEMY_DATABASE_URI = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.abspath('uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    MFA_ISSUER = "SecureCloud"
    SESSION_TYPE = "filesystem"
    SESSION_FILE_DIR = os.path.abspath("flask_session")
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode())

    @classmethod
    def wait_for_db(cls, max_retries=5, delay=3):
        """Wait for PostgreSQL to become available."""
        for attempt in range(max_retries):
            try:
                conn = psycopg2.connect(
                    host=cls.DB_HOST,
                    port=cls.DB_PORT,
                    user=cls.DB_USER,
                    password=cls.DB_PASSWORD,
                    dbname=cls.DB_NAME
                )
                conn.close()
                return True
            except psycopg2.OperationalError as e:
                if attempt == max_retries - 1:
                    raise RuntimeError(f"Failed to connect to database after {max_retries} attempts") from e
                sleep(delay)
        return False

# Initialize database URI
Config.SQLALCHEMY_DATABASE_URI = f'postgresql://{Config.DB_USER}:{Config.DB_PASSWORD}@{Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}'