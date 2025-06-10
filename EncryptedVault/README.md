# 🔐 Encrypted File Vault

A secure desktop application for safely encrypting, decrypting, and managing sensitive files. Built with Python, featuring password-based access, strong encryption, secure deletion, and an intuitive GUI.

![App Screenshot](screenshot.png)

## 🚀 Features
- **Master Password Protection** – Set and verify strong passwords using PBKDF2 + salt
- **Encrypted Vault** – Store/manage files with `.enc` extension
- **AES-128 Encryption** – Uses `cryptography`'s `Fernet` (CBC mode with HMAC)
- **Password Reset** – Decrypt and re-encrypt all files with new password
- **Secure File Deletion** – Shred files with multiple overwrite passes
- **Tkinter GUI** – Simple desktop interface

## 📦 Installation

### 1. Clone the Repository

git clone https://github.com/Mridul01154/EncryptedVault.git
cd EncryptedVault
pip install -r requirements.txt
python main.py

### 2. Install Requirements

> pip install -r requirements.txt


### 3. Run the App

> python main.py


### ✅ Requirements

- Python 3.8+
- cryptography
- tkinter

You can install the required package manually via:
> pip install cryptography

### 🔐 Security Notes
- Master password is stored as a derived key using PBKDF2 with SHA-256 and a unique salt.
- Files are encrypted using AES-128 with Fernet (symmetric key).
- Secure deletion is done by overwriting file contents with random data before removing.

### 🧪 Optional Features to Explore
- Auto-lock the vault after inactivity
- Command-line version
- Folder encryption support
- Biometric login or OTP-based 2FA

### 📸 Screenshots
You can add GUI screenshots here to showcase the interface.

### 📝 License
This project is licensed under the MIT License.

### 🙋 Author
- Mridul Gharami
- GitHub: @Mridul01154
