#!/usr/bin/env python3
"""
secure_email_gui.py

PyQt5 GUI for the Mini Secure Email project (AES-GCM + RSA-OAEP)

Features:
 - Generate RSA keypair
 - Sender: load receiver public key, compose message, encrypt, and either send via Gmail or save payload to file
 - Receiver: load private key, load/paste payload, decrypt message

Requirements:
 pip install pycryptodome PyQt5

Run:
 python secure_email_gui.py

Note: For Gmail sending use an App Password (recommended).
This is a demo/educational project; do not use in production as-is.
"""
import sys
import json
import base64
import getpass
import smtplib
from email.mime.text import MIMEText
from pathlib import Path

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox
)

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# ----- Crypto helpers -----

def generate_rsa_pair(bits=2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()


def save_bytes(path, data_bytes):
    with open(path, "wb") as f:
        f.write(data_bytes)


def load_rsa_public(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_rsa_private(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def aes_gcm_encrypt(plaintext_bytes, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return cipher.nonce, ct, tag


def aes_gcm_decrypt(nonce, ct, tag, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def rsa_oaep_encrypt(pubkey, data_bytes):
    return PKCS1_OAEP.new(pubkey).encrypt(data_bytes)


def rsa_oaep_decrypt(privkey, data_bytes):
    return PKCS1_OAEP.new(privkey).decrypt(data_bytes)


def make_payload_b64(enc_key, nonce, tag, ct):
    payload = {
        "encrypted_key": base64.b64encode(enc_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ct).decode()
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def parse_payload_b64(b64text):
    raw = base64.b64decode(b64text.encode())
    payload = json.loads(raw.decode())
    return (
        base64.b64decode(payload["encrypted_key"]),
        base64.b64decode(payload["nonce"]),
        base64.b64decode(payload["tag"]),
        base64.b64decode(payload["ciphertext"])
    )

# ----- Email send (Gmail STARTTLS) -----

def send_via_gmail(sender, app_password, recipient, subject, body_text):
    msg = MIMEText(body_text)
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    s = smtplib.SMTP("smtp.gmail.com", 587, timeout=30)
    s.ehlo()
    s.starttls()
    s.login(sender, app_password)
    s.sendmail(sender, [recipient], msg.as_string())
    s.quit()

# ----- GUI -----

class SecureEmailGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mini Secure Email — GUI")
        self.resize(800, 600)

        layout = QVBoxLayout()
        tabs = QTabWidget()

        # Tabs
        self.tab_gen = QWidget()
        self.tab_send = QWidget()
        self.tab_recv = QWidget()

        tabs.addTab(self.tab_gen, "Generate Keys")
        tabs.addTab(self.tab_send, "Send")
        tabs.addTab(self.tab_recv, "Receive")

        layout.addWidget(tabs)
        self.setLayout(layout)

        self._build_gen_tab()
        self._build_send_tab()
        self._build_recv_tab()

    # ----- gen tab -----
    def _build_gen_tab(self):
        l = QVBoxLayout()

        info = QLabel("Generate a 2048-bit RSA keypair. Save private key securely and share public key with senders.")
        l.addWidget(info)

        h = QHBoxLayout()
        self.priv_out = QLineEdit("private.pem")
        self.pub_out = QLineEdit("public.pem")
        btn_priv = QPushButton("Choose private path")
        btn_pub = QPushButton("Choose public path")
        btn_gen = QPushButton("Generate & Save")

        btn_priv.clicked.connect(lambda: self._choose_file(self.priv_out, save=True))
        btn_pub.clicked.connect(lambda: self._choose_file(self.pub_out, save=True))
        btn_gen.clicked.connect(self._on_generate_keys)

        h.addWidget(QLabel("Private key:"))
        h.addWidget(self.priv_out)
        h.addWidget(btn_priv)
        l.addLayout(h)

        h2 = QHBoxLayout()
        h2.addWidget(QLabel("Public key:"))
        h2.addWidget(self.pub_out)
        h2.addWidget(btn_pub)
        l.addLayout(h2)

        l.addWidget(btn_gen)
        self.tab_gen.setLayout(l)

    def _on_generate_keys(self):
        priv_path = self.priv_out.text().strip()
        pub_path = self.pub_out.text().strip()
        try:
            priv, pub = generate_rsa_pair()
            save_bytes(priv_path, priv)
            save_bytes(pub_path, pub)
            QMessageBox.information(self, "Done", f"Generated keys:\nPrivate -> {priv_path}\nPublic -> {pub_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate keys: {e}")

    # ----- send tab -----
    def _build_send_tab(self):
        l = QVBoxLayout()

        # Receiver public key
        row_pub = QHBoxLayout()
        self.pub_path = QLineEdit()
        btn_browse_pub = QPushButton("Load receiver public key")
        btn_browse_pub.clicked.connect(lambda: self._choose_file(self.pub_path, save=False))
        row_pub.addWidget(QLabel("Receiver public key:"))
        row_pub.addWidget(self.pub_path)
        row_pub.addWidget(btn_browse_pub)
        l.addLayout(row_pub)

        # SMTP / addresses
        row_from = QHBoxLayout()
        self.sender_email = QLineEdit()
        self.sender_pass = QLineEdit()
        self.sender_pass.setEchoMode(QLineEdit.Password)
        row_from.addWidget(QLabel("Your Gmail:"))
        row_from.addWidget(self.sender_email)
        row_from.addWidget(QLabel("App password:"))
        row_from.addWidget(self.sender_pass)
        l.addLayout(row_from)

        row_to = QHBoxLayout()
        self.to_email = QLineEdit()
        self.subject = QLineEdit()
        row_to.addWidget(QLabel("To:"))
        row_to.addWidget(self.to_email)
        row_to.addWidget(QLabel("Subject:"))
        row_to.addWidget(self.subject)
        l.addLayout(row_to)

        # Message text
        self.message_text = QTextEdit()
        self.message_text.setPlaceholderText("Type your message here...\nPress the buttons below to Encrypt & Send or Encrypt & Save payload to file")
        l.addWidget(self.message_text)

        # Buttons
        row_buttons = QHBoxLayout()
        btn_enc_send = QPushButton("Encrypt & Send")
        btn_enc_save = QPushButton("Encrypt & Save Payload")
        btn_enc_send.clicked.connect(self._on_encrypt_and_send)
        btn_enc_save.clicked.connect(self._on_encrypt_and_save)
        row_buttons.addWidget(btn_enc_send)
        row_buttons.addWidget(btn_enc_save)
        l.addLayout(row_buttons)

        self.tab_send.setLayout(l)

    def _on_encrypt_and_send(self):
        pub = self.pub_path.text().strip()
        if not pub:
            QMessageBox.warning(self, "Missing", "Receiver public key path required")
            return
        try:
            receiver_pub = load_rsa_public(pub)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load receiver public key: {e}")
            return

        text = self.message_text.toPlainText().encode()
        if not text:
            QMessageBox.warning(self, "Empty", "Message is empty")
            return

        # AES encrypt
        aes_key = get_random_bytes(32)
        nonce, ct, tag = aes_gcm_encrypt(text, aes_key)
        enc_key = rsa_oaep_encrypt(receiver_pub, aes_key)
        payload_b64 = make_payload_b64(enc_key, nonce, tag, ct)

        # send
        sender = self.sender_email.text().strip()
        app_pass = self.sender_pass.text().strip()
        recipient = self.to_email.text().strip()
        subject = self.subject.text().strip() or "Secure Message [Encrypted]"
        if not (sender and app_pass and recipient):
            QMessageBox.warning(self, "Missing", "Sender email, app password and recipient required to send")
            return

        try:
            send_via_gmail(sender, app_pass, recipient, subject, payload_b64)
            QMessageBox.information(self, "Sent", "Encrypted payload sent via Gmail. Ask recipient to paste email body into Receiver tab.")
        except Exception as e:
            QMessageBox.critical(self, "Send failed", f"Failed to send email: {e}")

    def _on_encrypt_and_save(self):
        pub = self.pub_path.text().strip()
        if not pub:
            QMessageBox.warning(self, "Missing", "Receiver public key path required")
            return
        try:
            receiver_pub = load_rsa_public(pub)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load receiver public key: {e}")
            return

        text = self.message_text.toPlainText().encode()
        if not text:
            QMessageBox.warning(self, "Empty", "Message is empty")
            return

        aes_key = get_random_bytes(32)
        nonce, ct, tag = aes_gcm_encrypt(text, aes_key)
        enc_key = rsa_oaep_encrypt(receiver_pub, aes_key)
        payload_b64 = make_payload_b64(enc_key, nonce, tag, ct)

        path, _ = QFileDialog.getSaveFileName(self, "Save payload to file", "payload.txt", "Text files (*.txt);;All files (*)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(payload_b64)
        QMessageBox.information(self, "Saved", f"Payload saved to {path}")

    # ----- receive tab -----
    def _build_recv_tab(self):
        l = QVBoxLayout()

        row_priv = QHBoxLayout()
        self.priv_path = QLineEdit()
        btn_priv = QPushButton("Load private key")
        btn_priv.clicked.connect(lambda: self._choose_file(self.priv_path, save=False))
        row_priv.addWidget(QLabel("Private key:"))
        row_priv.addWidget(self.priv_path)
        row_priv.addWidget(btn_priv)
        l.addLayout(row_priv)

        self.payload_text = QTextEdit()
        self.payload_text.setPlaceholderText("Paste base64 payload here OR click Load Payload from file")
        l.addWidget(self.payload_text)

        row_recv_buttons = QHBoxLayout()
        btn_load_payload = QPushButton("Load payload from file")
        btn_load_payload.clicked.connect(self._on_load_payload_file)
        btn_decrypt = QPushButton("Decrypt")
        btn_decrypt.clicked.connect(self._on_decrypt)
        row_recv_buttons.addWidget(btn_load_payload)
        row_recv_buttons.addWidget(btn_decrypt)
        l.addLayout(row_recv_buttons)

        self.plain_text = QTextEdit()
        self.plain_text.setReadOnly(True)
        l.addWidget(QLabel("Decrypted message:"))
        l.addWidget(self.plain_text)

        self.tab_recv.setLayout(l)

    def _on_load_payload_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open payload file", "", "Text files (*.txt);;All files (*)")
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            self.payload_text.setPlainText(f.read())

    def _on_decrypt(self):
        priv = self.priv_path.text().strip()
        if not priv:
            QMessageBox.warning(self, "Missing", "Private key path required")
            return
        try:
            privkey = load_rsa_private(priv)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load private key: {e}")
            return

        b64payload = self.payload_text.toPlainText().strip()
        if not b64payload:
            QMessageBox.warning(self, "No payload", "No payload provided")
            return

        try:
            enc_key, nonce, tag, ct = parse_payload_b64(b64payload)
            aes_key = rsa_oaep_decrypt(privkey, enc_key)
            plaintext = aes_gcm_decrypt(nonce, ct, tag, aes_key)
            self.plain_text.setPlainText(plaintext.decode("utf-8", errors="replace"))
            QMessageBox.information(self, "Success", "Payload decrypted successfully")
        except Exception as e:
            QMessageBox.critical(self, "Decrypt failed", f"Failed to decrypt payload: {e}")

    # ----- helpers -----
    def _choose_file(self, lineedit: QLineEdit, save=False):
        if save:
            path, _ = QFileDialog.getSaveFileName(self, "Choose file to save", "", "PEM files (*.pem);;All files (*)")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Choose file", "", "PEM files (*.pem);;All files (*)")
        if path:
            lineedit.setText(path)


# ----- main -----

def main():
    app = QApplication(sys.argv)
    gui = SecureEmailGUI()
    gui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
