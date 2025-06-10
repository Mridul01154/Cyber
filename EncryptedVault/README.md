# 🔐 Encrypted File Vault

A secure desktop application for safely encrypting, decrypting, and managing your sensitive files. Built using Python, it features password-based access, strong encryption (AES/Fernet), secure deletion, and an intuitive GUI.

---

## 🚀 Features

- 🔒 **Master Password Protection** – Set and verify a strong password using PBKDF2 + salt.
- 🗃️ **Encrypted Vault** – Store and manage encrypted files with `.enc` extension.
- 📦 **AES Encryption** – Uses `cryptography`'s `Fernet` (AES-128 in CBC mode with HMAC).
- 🔁 **Password Reset** – Seamlessly decrypt and re-encrypt all vault files with a new password.
- ❌ **Secure File Deletion** – Shred files with multiple overwrite passes.
- 🖥️ **Tkinter GUI** – Simple, interactive desktop interface.

---

## 📁 Folder Structure

EncryptedVault/
├── main.py # Entry point - login/setup GUI
├── vault.py # Main file vault window
├── auth.py # Master password handling (save/verify)
├── encryption.py # File encryption, decryption, and secure delete
├── file_utils.py # Password reset, password strength check
├── vault_files/ # Encrypted files folder (auto-created)
├── config.json # Stores hashed password & salts
├── requirements.txt # Required Python packages
├── .gitignore # Files to ignore in Git
└── README.md # This file


---

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/EncryptedVault.git
cd EncryptedVault

2. Install Requirements
bash
Copy
Edit
pip install -r requirements.txt
3. Run the App
bash
Copy
Edit
python main.py
✅ Requirements
Python 3.8+

cryptography

tkinter (built-in in most Python installations)

You can install dependencies via:

bash
Copy
Edit
pip install cryptography
🔐 Security Notes
Password is stored as a derived key using PBKDF2 with SHA-256 and a unique salt.

Files are encrypted using Fernet (AES 128-bit).

Secure deletion overwrites the file with random data before deleting.

🧪 Optional Features to Explore
Auto-lock the vault after inactivity

CLI version

Add support for folders

Biometric login or OTP-based 2FA

📸 Screenshots
You can upload screenshots of the GUI here if you want!

📝 License
This project is licensed under the MIT License.

🙋 Author
Mridul Gharami
GitHub: @Mridul01154

yaml
Copy
Edit

---

Would you like me to also generate:

- `requirements.txt`
- `.gitignore`
- `LICENSE` (MIT)

Let me know and I’ll generate all three instantly.

2/2









