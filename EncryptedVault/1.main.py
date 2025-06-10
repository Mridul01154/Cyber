import tkinter as tk 
from tkinter import messagebox, ttk
from file_utils import is_strong_password
from auth import is_first_time, save_password, verify_password
from vault import VaultApp

CONFIG_FILE="config.json"

def toggle_password(self):
    show = "" if self.show_pw.get() else "*"
    self.entry.config(show=show)
    if self.confirm_entry:
        self.confirm_entry.config(show=show)
class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Vault - Login")
        self.root.geometry("400x260") 
        self.root.resizable(False, False)

        self.attempts = 0
        self.max_attempts = 3

        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(expand=True)

        self.label = ttk.Label(self.main_frame, text="Enter Master Password:", font=("Segoe UI", 11))
        self.label.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")

        self.entry = ttk.Entry(self.main_frame, show="*", width=30)
        self.entry.grid(row=1, column=0, columnspan=2, pady=5)

        self.confirm_label = None
        self.confirm_entry = None

        self.button = ttk.Button(self.main_frame, text="Login", command=self.check_password)
        self.button.grid(row=5, column=0, columnspan=2, pady=15)

        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_checkbox = ttk.Checkbutton(
            self.main_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        self.show_password_checkbox.grid(row=2, column=0, columnspan=2, pady=(0, 10), sticky="w")

        if is_first_time():
            self.label.config(text="Create Master Password:")
            self.show_confirm_password()
            self.button.config(text="Set Password")
            self.strength_label = ttk.Label(self.main_frame, text="", font=("Segoe UI", 9))
            self.strength_label.grid(row=6, column=0, columnspan=2)

            self.entry.bind("<KeyRelease>", self.update_strength_label)

            self.show_password_checkbox.grid_configure(row=4)
            self.button.grid_configure(row=5)
            self.strength_label.grid_configure(row=6)

    def toggle_password_visibility(self):
        show = "" if self.show_password_var.get() else "*"
        self.entry.config(show=show)
        if self.confirm_entry:
            self.confirm_entry.config(show=show)

    def update_strength_label(self, event=None):
        password = self.entry.get()
        if is_strong_password(password):
            self.strength_label.config(text="Strong Password", foreground="green")
        elif len(password) >= 6:
            self.strength_label.config(text="Weak Password", foreground="orange")
        else:
            self.strength_label.config(text="Too Short", foreground="red")

    def show_confirm_password(self):
        self.confirm_label = ttk.Label(self.main_frame, text="Confirm Password:", font=("Segoe UI", 10))
        self.confirm_label.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="w")

        self.confirm_entry = ttk.Entry(self.main_frame, show="*", width=30)
        self.confirm_entry.grid(row=3, column=0, columnspan=2, pady=5)

    def check_password(self):
        password = self.entry.get()

        if is_first_time():
            confirm = self.confirm_entry.get() if self.confirm_entry else ""
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return
            if not is_strong_password(password):
                messagebox.showerror(
                    "Weak Password",
                    "Password must be at least 8 characters long and include:\n"
                    "- Uppercase & lowercase letters\n"
                    "- At least one number\n"
                    "- At least one special character"
                )
                return
            save_password(password)
            messagebox.showinfo("Success", "Password set successfully.")
            self.root.destroy()
            launch_main_app(password)
        else:
            if verify_password(password):
                messagebox.showinfo("Welcome", "Access granted.")
                self.root.destroy()
                launch_main_app(password)
            else:
                self.attempts += 1
                if self.attempts >= self.max_attempts:
                    messagebox.showerror("Too Many Attempts", "Maximum login attempts exceeded. Exiting.")
                    self.root.destroy()  
                else:
                    remaining = self.max_attempts - self.attempts
                    messagebox.showerror("Error", f"Incorrect password.\nAttempts left: {remaining}")

def launch_main_app(password):
    root = tk.Tk()
    app = VaultApp(root, password)
    root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginWindow(root)
    root.mainloop()
