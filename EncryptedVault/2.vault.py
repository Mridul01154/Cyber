import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import encryption
import auth
import file_utils
from file_utils import reset_password

VAULT_DIR = "vault_files"  

class VaultApp:
    def __init__(self, master, password):
        self.master = master
        self.password = password
        self.salt = auth.file_get_salt()

        if not os.path.exists(VAULT_DIR):
            os.makedirs(VAULT_DIR)

        master.title("Encrypted File Vault")
        master.geometry("700x450")
        master.resizable(False, False)

        style = ttk.Style()
        style.configure("TButton", font=("Segoe UI", 10), padding=5)
        style.configure("TLabel", font=("Segoe UI", 11))

        list_frame = ttk.Frame(master, padding=(10, 10))
        list_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(list_frame, text="Encrypted Files:").pack(anchor="w")

        self.file_list = tk.Listbox(list_frame, height=15, width=90, font=("Segoe UI", 10))
        self.file_list.pack(pady=(5, 10), fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(master, padding=(10, 10))
        btn_frame.pack()

        ttk.Button(btn_frame, text="Add File", command=self.add_file).grid(row=0, column=0, padx=6, pady=5)
        ttk.Button(btn_frame, text="Decrypt File", command=self.decrypt_file).grid(row=0, column=1, padx=6, pady=5)
        ttk.Button(btn_frame, text="Delete File", command=self.delete_file).grid(row=0, column=2, padx=6, pady=5)
        ttk.Button(btn_frame, text="Refresh List", command=self.refresh_file_list).grid(row=0, column=3, padx=6, pady=5)
        ttk.Button(btn_frame, text="Reset Password", command=self.reset_password_ui).grid(row=0, column=4, padx=6, pady=5)

        self.refresh_file_list()

    def refresh_file_list(self):
        self.file_list.delete(0, tk.END)
        files = os.listdir(VAULT_DIR)
        for f in files:
            self.file_list.insert(tk.END, f)

    def add_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return

        filename = os.path.basename(file_path)
        out_path = os.path.join(VAULT_DIR, filename + ".enc")

        try:
            encryption.encrypt_file(file_path, self.password, self.salt, out_path)
            messagebox.showinfo("Success", f"Encrypted and added:\n{filename}")
            self.refresh_file_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt file:\n{str(e)}")

    def reset_password_ui(self):
            reset_password(self.master)
            self.salt = auth.file_get_salt()


    def decrypt_file(self):
        selected = self.file_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select a file to decrypt.")
            return
        filename = self.file_list.get(selected[0])
        enc_path = os.path.join(VAULT_DIR, filename)

        save_path = filedialog.asksaveasfilename(title="Save Decrypted File As")
        if not save_path:
            return

        try:
            encryption.decrypt_file(enc_path, self.password, self.salt, save_path)
            messagebox.showinfo("Success", f"File decrypted and saved:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt file:\n{str(e)}")

    def delete_file(self):
        selected = self.file_list.curselection()
        if not selected:
            messagebox.showwarning("Warning", "Select a file to delete.")
            return
        filename = self.file_list.get(selected[0])
        file_path = os.path.join(VAULT_DIR, filename)

        confirm = messagebox.askyesno("Confirm Delete", f"Securely delete:\n{filename}?")
        if confirm:
            try:
                file_utils.secure_delete(file_path)
                messagebox.showinfo("Deleted", f"File securely deleted:\n{filename}")
                self.refresh_file_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete file:\n{str(e)}")
