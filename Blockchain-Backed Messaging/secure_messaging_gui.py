import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json

SERVER_HOST = 'local ip'
SERVER_PORT = 12345

class BlockchainClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Blockchain Messenger")
        self.root.geometry("800x560")
        self.is_dark_mode = False

        self.setup_styles()
        self.build_gui()
        self.set_theme("light")

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", font=("Segoe UI", 11))
        self.style.configure("TEntry", padding=5)
        self.style.configure("TButton", font=("Segoe UI", 11), padding=5)

    def set_theme(self, mode):
        bg = "#121212" if mode == "dark" else "#f4f4f4"
        fg = "#ffffff" if mode == "dark" else "#000000"
        text_bg = "#1e1e1e" if mode == "dark" else "#ffffff"

        self.root.configure(bg=bg)
        self.input_frame.configure(bg=bg)
        self.title_label.configure(background=bg, foreground=fg)

        for widget in self.input_frame.winfo_children():
            if isinstance(widget, (ttk.Label, ttk.Entry)):
                widget.configure(style="TLabel")

        self.output.configure(bg=text_bg, fg=fg, insertbackground=fg)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.set_theme("dark" if self.is_dark_mode else "light")

    def build_gui(self):
        self.title_label = ttk.Label(self.root, text="Blockchain Messenger", font=("Segoe UI", 18, "bold"))
        self.title_label.pack(pady=10)

        self.input_frame = tk.Frame(self.root)
        self.input_frame.pack(pady=10)

        ttk.Label(self.input_frame, text="Sender:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.sender_entry = ttk.Entry(self.input_frame, width=30)
        self.sender_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.input_frame, text="Message:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.message_entry = ttk.Entry(self.input_frame, width=50)
        self.message_entry.grid(row=1, column=1, padx=5, pady=5)

        self.send_button = ttk.Button(self.input_frame, text="🚀 Send Message", command=self.send_message)
        self.send_button.grid(row=2, column=1, pady=10)

        self.theme_button = ttk.Button(self.input_frame, text="🌓 Toggle Dark Mode", command=self.toggle_theme)
        self.theme_button.grid(row=2, column=0, pady=10)

        self.output = scrolledtext.ScrolledText(self.root, width=95, height=20, font=("Consolas", 10), borderwidth=1, relief="solid")
        self.output.pack(padx=10, pady=10)

    def send_message(self):
        sender = self.sender_entry.get().strip()
        message = self.message_entry.get().strip()

        if not sender or not message:
            messagebox.showwarning("Input Error", "Sender and message required.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_HOST, SERVER_PORT))
                data = json.dumps({'sender': sender, 'message': message})
                s.send(data.encode())
                response = s.recv(8192).decode()
                chain = json.loads(response)
                self.display_chain(chain)
        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not reach server:\n{e}")

        self.sender_entry.delete(0, tk.END)
        self.message_entry.delete(0, tk.END)

    def display_chain(self, chain):
        self.output.delete(1.0, tk.END)
        for block in chain:
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
