import os
import tkinter as tk
from tkinter import messagebox, ttk
import shutil
import re
from auth import save_password, verify_password, file_get_salt
import subprocess
import encryption
import sys

CONFIG_FILE = "config.json"

class PasswordResetDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Reset Password")
        self.top.geometry("450x380")
        self.top.resizable(False, False)
        self.top.transient(parent)
        self.top.grab_set()

        ttk.Label(self.top, text="Enter current password:").pack(pady=(10, 0))
        self.current_entry = ttk.Entry(self.top, show="*")
        self.current_entry.pack(pady=5)

        ttk.Label(self.top, text="Enter new password:").pack(pady=(10, 0))
        self.new_entry = ttk.Entry(self.top, show="*")
        self.new_entry.pack(pady=5)
        self.new_entry.bind("<KeyRelease>", self.update_strength_label)

        self.strength_label = ttk.Label(self.top, text="", font=("Segoe UI", 9))
        self.strength_label.pack(pady=(0, 5))

        ttk.Label(self.top, text="Confirm new password:").pack(pady=(10, 0))
        self.confirm_entry = ttk.Entry(self.top, show="*")
        self.confirm_entry.pack(pady=5)

        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_checkbox = ttk.Checkbutton(
            self.top,
            text="Show Passwords",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_checkbox.pack(pady=10)

        ttk.Button(self.top, text="Submit", command=self.on_submit).pack(pady=10)
        
        self.result = None

    def update_strength_label(self, event=None):
        password = self.new_entry.get()
        if is_strong_password(password):
            self.strength_label.config(text="Strong Password", foreground="green")
        elif len(password) >= 6:
            self.strength_label.config(text="Weak Password", foreground="orange")
        else:
            self.strength_label.config(text="Too Short", foreground="red")

    def toggle_password_visibility(self):
        show = "" if self.show_password_var.get() else "*"
        self.current_entry.config(show=show)
        self.new_entry.config(show=show)
        self.confirm_entry.config(show=show)

    def on_submit(self):
        current = self.current_entry.get()
        new = self.new_entry.get()
        confirm = self.confirm_entry.get()
        self.result = (current, new, confirm)
        self.top.destroy()



def is_strong_password(pw):
    return (
        len(pw) >= 8 and
        re.search(r"[a-z]", pw) and
        re.search(r"[A-Z]", pw) and
        re.search(r"\d", pw) and
        re.search(r"[^\w\s]", pw) 
    )

VAULT_DIR = "vault_files"
def reset_password(root):

    dialog = PasswordResetDialog(root)
    root.wait_window(dialog.top)

    if not dialog.result:
        return
    current_password, new_password, confirm_password = dialog.result

    if not verify_password(current_password):
        messagebox.showerror("Error", "Incorrect current password.")
        return
    
    if not new_password or new_password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return

    if not is_strong_password(new_password):
        messagebox.showerror(
            "Weak Password",
            "Password must be at least 8 characters and include:\n"
            "- Uppercase and lowercase letters\n"
            "- At least one digit\n"
            "- At least one special character"
        )
        return

    temp_dir = "temp_vault"  

    try:

        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

        os.makedirs(temp_dir, exist_ok=True)

        old_salt = file_get_salt()
        files = [f for f in os.listdir(VAULT_DIR) if f.endswith(".enc")]

        failed_files = []

        for f in files:
            encrypted_path = os.path.join(VAULT_DIR, f)
            decrypted_path = os.path.join(temp_dir, f[:-4])
            success = encryption.decrypt_file(encrypted_path, current_password, old_salt, decrypted_path, suppress_popup=True)
            if not success:
                failed_files.append(f)

        if failed_files:
            messagebox.showwarning(
                "Partial Failure",
                "Some files could not be decrypted:\n" + "\n".join(failed_files)
            )

        for f in files:
            encryption.secure_delete(os.path.join(VAULT_DIR, f))

        save_password(new_password)
        new_salt = file_get_salt()

        for f in os.listdir(temp_dir):
            plain_path = os.path.join(temp_dir, f)
            encrypted_path = os.path.join(VAULT_DIR, f + ".enc")
            success = encryption.encrypt_file(plain_path, new_password, new_salt, encrypted_path,suppress_popup=True)
            if not success:
                print(f"Failed to encrypt: {encrypted_path}")

        shutil.rmtree(temp_dir)

        messagebox.showinfo("Success", "Password and all files re-encrypted successfully.")
        subprocess.Popen([sys.executable] + sys.argv)
        root.destroy()
       
    except Exception as e:
        if os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
        messagebox.showerror("Error", f"Reset failed:\n{str(e)}")
