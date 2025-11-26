# Secure-Email-Client-Using-Hybrid-Cryptography-RSA-AES-with-GUI
End-to-end encrypted email system with PyQt5 GUI, payload encryption &amp; decryption.
📌 Secure Email Client (RSA + AES + GUI)

A mini-project implementing a hybrid cryptographic secure email system using:

AES-256-GCM (for message encryption + integrity)

RSA-2048-OAEP (for key wrapping)

PyQt5 GUI (Generate Keys, Send, Receive)

Gmail SMTP support

Encrypted payload export

This project demonstrates end-to-end encryption using hybrid cryptography.

🚀 Features
🔐 Hybrid Encryption

AES-256-GCM encrypts the message

RSA-2048 encrypts the AES session key

Payload is packed as Base64 JSON

🖥 GUI (PyQt5)

Generate RSA public/private keys

Encrypt message & save to payload file

Optional: send via Gmail SMTP

Decrypt payload using private key

🧪 CLI Version Included

genkeys

send

recv

📦 Installation
Step 1: Install dependencies
pip install pycryptodome PyQt5

Step 2: Run GUI
python secure_email_gui.py

🗂 Project Structure
secure-email-client/
|── secure_email_gui.py           # GUI version
|── secure_email_cli.py           # CLI tools
|── payload_examples/
|     └── sample_payload.txt
|── keys/
|     ├── receiver_public.pem
|     └── DO_NOT_UPLOAD_PRIVATE_KEY.txt
|── screenshots/
|── README.md

🛠 Usage
1️⃣ Generate RSA Keys

Open Generate Keys tab

Choose file paths

Click "Generate & Save"

Share only the public key

2️⃣ Encrypt a Message (Sender)

Load receiver public key

Type message

Click Encrypt & Save Payload

Creates payload.txt

Optional: Send via Gmail (requires App Password)

3️⃣ Decrypt Message (Receiver)

Load private key

Load payload file

Click Decrypt

Plaintext appears immediately

📄 Example Payload (Base64 Encoded JSON)
ewogICJlbmNyeXB0ZWRfa2V5IjogIi4uLiIsCiAgIm5vbmNlIjogIi4uLiIsCiAgInRhZyI6ICIuLi4iLAogICJjaXBoZXJ0ZXh0IjogIi4uLi4iCn0=

📚 Technologies Used

Python

PyQt5 (GUI)

PyCryptodome (RSA + AES)

SMTP (Gmail)
