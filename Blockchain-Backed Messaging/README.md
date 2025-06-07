# 🌐 Blockchain-Backed Secure Messenger

> A secure, GUI-based messaging application that stores all messages on a verifiable blockchain using Python, sockets, TLS encryption, and Tkinter.

---

## 😮 What It Does

This project is a desktop messenger with the following features:

✅ **Blockchain Storage**: Every message sent is stored as a block with a timestamp, sender info, message content, previous hash, and cryptographic hash.

✅ **TLS Encryption**: All communication is protected using SSL/TLS certificates, ensuring message confidentiality and integrity.

✅ **Multithreaded Server**: Supports concurrent client connections via Python threading.

✅ **GUI Client**: Built with Tkinter, the client offers a modern theme-switching interface, chain visualization, and responsive input.

---

## 📷 Screenshots

> Located in the [`docs`](https://github.com/Mridul01154/Cyber/tree/main/Blockchain-Backed%20Messaging/docs) folder of the repo.

![Light Mode](https://github.com/Mridul01154/Cyber/blob/main/Blockchain-Backed%20Messaging/docs/Screenshot%202025-06-06%20175630.png)
![Dark Mode](https://github.com/Mridul01154/Cyber/blob/main/Blockchain-Backed%20Messaging/docs/Screenshot%202025-06-06%20110553.png)

---

## ⚙️ Tech Stack

| Layer     | Technology         |
|-----------|--------------------|
| Language  | Python 3           |
| GUI       | Tkinter + ttk      |
| Backend   | `socket`, `ssl`, `threading` |
| Blockchain| `hashlib`, JSON, datetime |

---

## 🛠️ How to Run Locally

### 🔐 1. Generate TLS Certificates

You can use the provided script:
```bash
python generate_cert.py
```
> Or manually:
```bash
openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout key.pem
```

### 🖥 2. Run the Server
```bash
python server.py
```

### 💬 3. Run the Client GUI
```bash
python secure_messaging_gui.py
```

### 🧲 Note:
- Ensure both scripts use the same `cert.pem`
- Update `SERVER_HOST` in `secure_messaging_gui.py` with your IP or domain

---

## 💡 Features Overview

- 🔐 **True end-to-end encryption where the server cannot decrypt messages**
- 🔒 **TLS-Secured Socket Communication**
- 🧱 **Blockchain with Previous Hash & Integrity**
- 🪟 **Modern Tkinter UI with Dark Mode Toggle**
- 🔄 **Chain Refresh & Display**
- 🧵 **Handles Multiple Clients via Threads**

---

## 📂 Project Structure

```
Blockchain-Backed Messaging/
├── server.py             # TLS server with blockchain
├── secure_messaging_gui.py  # Tkinter-based GUI client
├── generate_cert.py      # Helper script to generate TLS certificates
├── cert.pem
├── key.pem
├── docs/                 # Screenshots and demo media
└── README.md
```

---

## 📈 Future Improvements

- 🔑 Implement asymmetric key exchange for secure key distribution
- 🌍 Optional online deployment with Flask/Render
- 📂 Persist blockchain data to disk
- 👥 Add user authentication
- 🔗 Broadcast updates to all connected clients
- 🌐 Web-based client interface

---

## 🧑‍💻 Author

**Mridul Gharami**  
📧 [GitHub Profile](https://github.com/Mridul01154)  
📌 BSc Computer Science Student

---

## 📜 License

This project is licensed under the MIT License — feel free to fork, modify, and share!

---

## ⭐️ Show Your Support
If you like this project:
- ⭐ Star the repo
- 🛠 Contribute ideas or PRs
- 📢 Share it with other Python or blockchain learners
