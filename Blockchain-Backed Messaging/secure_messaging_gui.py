import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import ssl
import threading
import time

SERVER_HOST = 'ip address'
SERVER_PORT = 9999

class BlockchainClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Blockchain Messenger")
        self.root.geometry("800x560")
        self.is_dark_mode = False
        self.lock = threading.Lock()
        self.listener_socket = None
        self.start_auto_refresh()

        self.setup_styles()
        self.build_gui()
        self.set_theme("light")

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("Light.TLabel", background="#f4f4f4", foreground="#000000", font=("Segoe UI", 11))
        self.style.configure("Light.TEntry", fieldbackground="#ffffff", foreground="#000000")
        self.style.configure("Light.TButton", font=("Segoe UI", 11), padding=5)

        self.style.configure("Dark.TLabel", background="#121212", foreground="#ffffff", font=("Segoe UI", 11))
        self.style.configure("Dark.TEntry", fieldbackground="#1e1e1e", foreground="#ffffff")
        self.style.configure("Dark.TButton", font=("Segoe UI", 11), padding=5)

    def set_theme(self, mode):
        if mode == "dark":
            bg = "#121212"
            fg = "#ffffff"
            text_bg = "#1e1e1e"
            label_style = "Dark.TLabel"
            entry_style = "Dark.TEntry"
            button_style = "Dark.TButton"
            self.tls_status.configure(background="#121212")
            self.block_count_label.configure(background="#121212",foreground="#ffffff")
        else:
            bg = "#f4f4f4"
            fg = "#000000"
            text_bg = "#ffffff"
            label_style = "Light.TLabel"
            entry_style = "Light.TEntry"
            button_style = "Light.TButton"
            self.tls_status.configure(background="#ffffff")
            self.block_count_label.configure(background="#ffffff",foreground="#121212")

        self.root.configure(bg=bg)
        self.input_frame.configure(bg=bg)
        self.title_label.configure(style=label_style)

        for widget in self.input_frame.winfo_children():
            if isinstance(widget, ttk.Label):
                widget.configure(style=label_style)
            elif isinstance(widget, ttk.Entry):
                widget.configure(style=entry_style)
            elif isinstance(widget, ttk.Button):
                widget.configure(style=button_style)

        self.output.configure(bg=text_bg, fg=fg, insertbackground=fg)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.set_theme("dark" if self.is_dark_mode else "light")

    def refresh_chain(self):
        try:
            context = ssl.create_default_context(cafile="cert.pem")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=SERVER_HOST) as s:
                    s.send(json.dumps({"type": "refresh"}).encode())
                    response = s.recv(8192).decode()
                    chain = json.loads(response)
                    self.display_chain(chain)
                    self.tls_status.configure(text="🔒 TLS: Connected", fg="green")
                    self.set_status("Chain refreshed successfully.", is_error=False)

        except Exception as e:
            self.tls_status.configure(text="🔒 TLS: Disconnected", fg="red")
            self.set_status(f"Refresh failed: {e}", is_error=True)
            messagebox.showwarning("Connection Error", "Server Down.")

    def set_status(self, message, level="info"):
        color = {"info": "blue", "success": "green", "error": "red", "warning": "orange"}.get(level, "black")
        self.status_var.set(message)
        self.status_label.configure(foreground=color)


    def build_gui(self):
        self.title_label = ttk.Label(self.root, text="Blockchain Messenger", font=("Segoe UI", 18, "bold"))
        self.title_label.pack(pady=10)

        self.tls_status = tk.Label(self.root, text="🔒 TLS: Disconnected", fg="red", font=("Segoe UI", 10, "bold"))
        self.tls_status.pack()

        self.block_count_label = ttk.Label(self.root, text="📦 Total Blocks: 0", font=("Segoe UI", 10))
        self.block_count_label.pack()

        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(pady=10)

        ttk.Label(self.input_frame, text="Sender:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.sender_entry = ttk.Entry(self.input_frame, width=30)
        self.sender_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.input_frame, text="Message:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.message_entry = ttk.Entry(self.input_frame, width=50)
        self.message_entry.grid(row=1, column=1, padx=5, pady=5)
        self.message_entry.bind("<Return>", lambda event: self.send_message())

        self.send_button = ttk.Button(self.input_frame, text="🚀 Send Message", command=self.send_message, )
        self.send_button.grid(row=2, column=1, pady=10)

        self.theme_button = ttk.Button(self.input_frame, text="🌓 Toggle Dark Mode", command=self.toggle_theme)
        self.theme_button.grid(row=2, column=0, pady=10)

        self.refresh_button = ttk.Button(self.input_frame, text="⟳ Refresh Chain", command=self.refresh_chain)
        self.refresh_button.grid(row=2, column=2, padx=5, pady=10)

        self.output = scrolledtext.ScrolledText(self.root, width=95, height=20, font=("Consolas", 10), borderwidth=1, relief="solid")
        self.output.pack(padx=10, pady=10)

        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(self.root, textvariable=self.status_var, anchor="w", foreground="red")
        self.status_label.pack(fill="x", padx=10, pady=(0, 5))

        self.status_label = ttk.Label(self.root, text="Welcome.", font=("Segoe UI", 10, "italic"))
        self.status_label.pack(pady=5)

    def set_status(self, message, is_error=False):
        self.status_var.set(message)
        self.status_label.configure(foreground="red" if is_error else "green")

    def start_auto_refresh(self):
        threading.Thread(target=self.listen_for_updates, daemon=True).start()

    def listen_for_updates(self):
        while True:
            try:
                context = ssl.create_default_context(cafile="cert.pem")
                context.check_hostname = False
                context.verify_mode = ssl.CERT_REQUIRED
                with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=SERVER_HOST) as s:
                        with self.lock:
                            self.listener_socket = s
                        while True:
                            response = s.recv(8192).decode()
                            if response:
                                chain = json.loads(response)
                                self.root.after(0, lambda: self.display_chain(chain))
            except Exception as e:
                self.root.after(0, lambda: self.set_status(f"Auto-update error: {e}", is_error=True))
                time.sleep(5)


    def send_message(self):
        sender = self.sender_entry.get().strip()
        message = self.message_entry.get().strip()

        if not sender or not message:
            messagebox.showwarning("Input Error", "Sender and message required.")
            return

        try:
            context = ssl.create_default_context(cafile="cert.pem")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=SERVER_HOST) as s:
                    data = json.dumps({'sender': sender, 'message': message})
                    s.send(data.encode())
                    response = s.recv(8192).decode()
                    chain = json.loads(response)
                    self.display_chain(chain)
                    self.tls_status.configure(text="🔒 TLS: Connected", fg="green")
                    self.set_status("Connected securely.", is_error=False)
        except FileNotFoundError:
            messagebox.showerror("Certificate Error", "Trusted certificate (cert.pem) not found.")
        except Exception as e:
            self.tls_status.configure(text="🔒 TLS: Disconnected", fg="red")
            self.set_status(f"Connection failed: {e}", is_error=True)
            messagebox.showwarning("Connection Error", "Server Down.")

        self.message_entry.delete(0, tk.END)
        self.message_entry.focus_set()

    def display_chain (self, chain):
        self.block_count_label.configure(text=f"📦 Total Blocks: {len(chain)}")
        self.output.delete(1.0, tk.END)
        for block in reversed(chain):
            initials = block['sender'][0].upper() if block['sender'] else "?"
            self.output.insert(tk.END, f"\n👤 [{initials}] {block['sender']}  📅 {block['timestamp']}\n", "bold")
            self.output.insert(tk.END, f"💬 {block['message']}\n", "msg")
            self.output.insert(tk.END, f"🔁 Prev Hash: {block['previous_hash']}\n")
            self.output.insert(tk.END, f"🔒 Hash: {block['hash']}\n")
            self.output.insert(tk.END, "—" * 80 + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = BlockchainClientApp(root)
    root.mainloop() 
