from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, DateTime, JSON, text
from sqlalchemy.orm import sessionmaker, scoped_session, relationship, declarative_base
from datetime import datetime, timedelta
import uuid
import time
import logging
from config import Config


logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

Base = declarative_base()

def create_db_engine():
    return create_engine(
        Config.SQLALCHEMY_DATABASE_URI,
        pool_pre_ping=True,
        pool_recycle=3600
    )

engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Session = scoped_session(SessionLocal)
Base.query = Session.query_property()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    roles = Column(JSON, default=["user"])
    totp_secret = Column(String(32))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    buckets = relationship("Bucket", back_populates="user")
    shared_links = relationship("SharedLink", back_populates="user")

class Bucket(Base):
    __tablename__ = "buckets"
    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    is_encrypted = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user = relationship("User", back_populates="buckets")
    files = relationship("File", back_populates="bucket")

class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True)
    filename = Column(String(100), nullable=False)
    encrypted_path = Column(String(255), nullable=False)
    bucket_id = Column(Integer, ForeignKey("buckets.id"))
    salt = Column(String(100))
    size = Column(Integer)
    mime_type = Column(String(50))
    upload_time = Column(DateTime, default=datetime.utcnow)
    hash = Column(String(64))
    bucket = relationship("Bucket", back_populates="files")
    versions = relationship("FileVersion", back_populates="file")
    shared_links = relationship("SharedLink", back_populates="file")

class FileVersion(Base):
    __tablename__ = "file_versions"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("files.id"))
    version = Column(Integer, nullable=False)
    filepath = Column(String(255), nullable=False)
    size = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    file = relationship("File", back_populates="versions")
    user = relationship("User")

class SharedLink(Base):
    __tablename__ = "shared_links"
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("files.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String(50), unique=True, default=lambda: str(uuid.uuid4()))
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=7))
    is_active = Column(Boolean, default=True)
    download_count = Column(Integer, default=0)
    max_downloads = Column(Integer)
    password_hash = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    file = relationship("File", back_populates="shared_links")
    user = relationship("User", back_populates="shared_links")

def init_db():
    Base.metadata.create_all(bind=engine)

def drop_db():
    Base.metadata.drop_all(bind=engine)

if __name__ == '__main__':
    init_db()
    print("Database tables created successfully")