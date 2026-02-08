# 🔐 Cyber Encryption Tool

A cybersecurity-focused encryption system that supports **AES, DES, and RSA** algorithms with both **GUI (Tkinter)** and **Web (Flask)** interfaces.  
The project demonstrates **secure encryption, decryption, hashing, and key handling** using industry-aligned cryptographic practices.

---

## 🚀 Features

- 🔒 Text Encryption & Decryption
- 🔑 Algorithms Supported:
  - AES (Symmetric Encryption)
  - DES (Legacy Symmetric Encryption)
  - RSA (Asymmetric Encryption)
- 🧾 SHA-256 Hashing
- 📁 File Encryption
- 🖥️ GUI Application (Tkinter)
- 🌐 Web Application (Flask)
- 🎨 Cyber-themed UI (Nabla, Orbitron, Montserrat)
- 🧠 Stateless Decryption (No session dependency)

---

## 🏗️ Project Structure

TEXT-ENCRYPTION/
│
├── crypto_utils.py
├── gui_app.py
├── web_app.py
├── requirements.txt
│
├── templates/
│ └── index.html
│
└── static/
└── style.css
---
## ⚙️ Installation

### 1️⃣ Clone the repository

git clone https://github.com/<your-username>/text-encryption-tool.git
cd text-encryption-tool

### 2️⃣ Create virtual environment
python -m venv venv
Activate:
Windows:
venv\Scripts\activate
Linux / macOS:
source venv/bin/activate

### 3️⃣ Install dependencies
pip install -r requirements.txt
▶️ Running the Applications
🖥️ GUI Version
python gui_app.py
🌐 Web Version
python web_app.py
Open in browser:
http://127.0.0.1:5000
---
🔐 How Encryption Works
AES / DES
Generates a secret key + nonce
Same key is used for encryption and decryption
RSA
Uses public key for encryption
Uses private key for decryption
---
⚠️ Decryption requires the correct cryptographic parameters provided by the user.

🧠 Security Concepts Demonstrated
Symmetric vs Asymmetric Encryption
Key Management
Stateless Cryptographic Design
Hashing for Integrity
Secure UI/UX for cryptographic tools

📌 Future Enhancements
Password-based encryption (PBKDF2)
Hybrid Encryption (AES + RSA)
File Decryption
HTTPS Deployment
Audit Logging

👨‍💻 Author
Trinabha Dixit
Cybersecurity Student | Blockchain & Security Enthusiast

📜 Disclaimer
This project is for educational purposes only and should not be used in production without security hardening.
---
