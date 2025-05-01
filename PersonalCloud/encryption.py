
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

def generate_key(password: str, salt: bytes = None) -> tuple:
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key), salt

def encrypt_file(file_path: str, key: Fernet) -> str:
    with open(file_path, "rb") as f:
        data = f.read()
    encrypted_data = key.encrypt(data)
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)
    os.remove(file_path)
    return encrypted_path

def decrypt_file(encrypted_path: str, key: Fernet) -> bytes:
    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()
    return key.decrypt(encrypted_data)