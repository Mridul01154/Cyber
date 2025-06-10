import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from tkinter import messagebox
import os

def secure_delete(filepath, passes=3):
    if not os.path.isfile(filepath):
        print(f"[Warning] File not found: {filepath}")
        return

    length = os.path.getsize(filepath)

    try:
        with open(filepath, 'ba+', buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                random_data = os.urandom(length)
                f.write(random_data)
                f.flush()
                os.fsync(f.fileno())
        os.remove(filepath)
        print(f"Securely deleted: {filepath}")
    except Exception as e:
        print(f"[Error] Could not securely delete {filepath}: {e}")

def safe_write(filepath, data, mode='wb'):
    try:
        with open(filepath, mode) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"[Error] Could not write to {filepath}: {e}")

def safe_read(filepath, mode='rb'):
    try:
        with open(filepath, mode) as f:
            return f.read()
    except Exception as e:
        print(f"[Error] Could not read {filepath}: {e}")
        return None

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)  

def get_fernet(password: str, salt: bytes) -> Fernet:

    key = derive_key(password, salt)
    return Fernet(key)

def encrypt_file(filepath, password, salt, out_path, suppress_popup=False):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        if not suppress_popup:
            messagebox.showerror("Read Error", f"Could not read file:\n{e}")
        return False  

    try:
        fernet = get_fernet(password, salt)
        encrypted_data = fernet.encrypt(data)
        safe_write(out_path, encrypted_data)
        if not suppress_popup:
            messagebox.showinfo("Success", f"File encrypted and saved to:\n{out_path}")
        return True  
    except Exception as e:
        if not suppress_popup:
            messagebox.showerror("Encryption Error", f"Encryption failed:\n{e}")
        return False 


def decrypt_file(enc_path, password, salt, out_path, suppress_popup=False):
    try:
        encrypted_data = safe_read(enc_path)
        if encrypted_data is None:
            if not suppress_popup:
                messagebox.showerror("Error", f"Could not read file: {enc_path}")
            return False  

        fernet = get_fernet(password, salt)
        decrypted_data = fernet.decrypt(encrypted_data)

        safe_write(out_path, decrypted_data)
        if not suppress_popup:
            messagebox.showinfo("Success", f"File decrypted and saved to:\n{out_path}")
        return True  

    except Exception as e:
        if not suppress_popup:
            messagebox.showerror("Decryption Error", f"Decryption failed:\n{e}")
        return False  


def delete_file(filepath):
    confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to securely delete:\n{filepath}?")
    if confirm:
        secure_delete(filepath)
        messagebox.showinfo("Deleted", f"File securely deleted:\n{filepath}")
    else:
        messagebox.showinfo("Cancelled", "Deletion cancelled.")


