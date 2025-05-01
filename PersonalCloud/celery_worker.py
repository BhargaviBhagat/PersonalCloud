# celery_worker.py
from celery import Celery
from encryption import generate_key
from hashlib import sha256
import os
from database import Bucket, File, FileVersion, Session
from app import app

celery = Celery(
    'celery_worker',
    broker='redis://redis:6379/0',
    backend='redis://redis:6379/1'
)

celery.conf.update(
    result_expires=3600,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

@celery.task(name='celery_worker.encrypt_and_store')
def encrypt_and_store(file_data, filename, bucket_id, user_password):
    session = Session()
    try:
        bucket = session.query(Bucket).get(bucket_id)
        if not bucket:
            raise ValueError("Bucket not found")
        
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(bucket.user_id))
        os.makedirs(user_dir, exist_ok=True)
        
        bucket_dir = os.path.join(user_dir, bucket.name)
        os.makedirs(bucket_dir, exist_ok=True)
        
        file_path = os.path.join(bucket_dir, filename)
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        file_hash = sha256(file_data).hexdigest()
        key, salt = generate_key(user_password)
        encrypted_path = encrypt_file(file_path, key)
        
        existing_file = session.query(File).filter_by(bucket_id=bucket_id, filename=filename).first()
        
        if existing_file:
            version_count = session.query(FileVersion).filter_by(file_id=existing_file.id).count() + 1
            new_version = FileVersion(
                file_id=existing_file.id,
                version=version_count,
                encrypted_path=existing_file.encrypted_path
            )
            session.add(new_version)
            existing_file.encrypted_path = encrypted_path
            existing_file.salt = salt
            existing_file.hash = file_hash
        else:
            new_file = File(
                bucket_id=bucket_id,
                filename=filename,
                encrypted_path=encrypted_path,
                salt=salt,
                hash=file_hash
            )
            session.add(new_file)
        
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def encrypt_file(file_path: str, key: Fernet) -> str:
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = key.encrypt(data)
    encrypted_path = file_path + '.enc'
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
    os.remove(file_path)
    return encrypted_path