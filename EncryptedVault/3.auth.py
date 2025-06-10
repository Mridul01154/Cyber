import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

CONFIG_FILE = "config.json"

def is_first_time():
    return not os.path.exists(CONFIG_FILE)

def save_password(password):
    salt = os.urandom(16)
    file_salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    with open(CONFIG_FILE, "w") as f:
        json.dump({
            "salt": base64.b64encode(salt).decode(),
            "key": base64.b64encode(key).decode(),
            "file_salt": base64.b64encode(file_salt).decode()
        }, f)

def verify_password(password):
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        salt = base64.b64decode(data["salt"])
        stored_key = base64.b64decode(data["key"])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        kdf.verify(password.encode(), stored_key)
        return True
    except Exception:
        return False

def get_salt():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r") as f:
        data = json.load(f)
    return base64.b64decode(data["salt"])

def file_get_salt():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r") as f:
        data = json.load(f)
    return base64.b64decode(data["file_salt"])
