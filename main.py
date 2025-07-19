import random
import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style
from ttkbootstrap.constants import *
from cryptography.fernet import Fernet
import requests

# Load key (or generate a new one)
def load_key():
    try:
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

# Encrypt message
def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode()).decode()

# Decrypt message
def decrypt_message(encrypted_message, key):
    return Fernet(key).decrypt(encrypted_message.encode()).decode()

# Save encrypted message to file
def save_encrypted(encrypted_text):
    with open("encrypted.txt", "w") as f:
        f.write(encrypted_text)

# Load encrypted message
def load_encrypted():
    with open("encrypted.txt", "r") as f:
        return f.read()

# Send OTP with Infobip using REST API
def send_otp_infobip(phone_number, otp):
    API_KEY = "9e20d79a6156c0c13347f798559edbb4-4a1530a6-de25-4822-999b-18c6c5a7cf08"  
    BASE_URL = "https://lqyv5d.api.infobip.com"  

    url = f"{BASE_URL}/sms/2/text/advanced"
    headers = {
        "Authorization": f"App {API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    payload = {
        "messages": [
            {
                "from": "InfoSMS",
                "destinations": [{"to": phone_number}],
                "text": f"Your OTP is: {otp}"
            }
        ]
    }

    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()  # Raises error if request fails
    return response

# Encrypt & Send OTP
def encrypt_and_send():
    message = message_input.get("1.0", tk.END).strip()
    phone = phone_input.get().strip()

    if not message or not phone:
        output_label.config(text="Please enter message and phone number!", bootstyle="danger")
        return

    key = load_key()
    encrypted = encrypt_message(message, key)
    save_encrypted(encrypted)

    otp = str(random.randint(100000, 999999))
    with open("otp.txt", "w") as f:
        f.write(otp)

    try:
        send_otp_infobip(phone, otp)
        output_label.config(text="Message encrypted & OTP sent!", bootstyle="success")
    except Exception as e:
        output_label.config(text=f"Failed to send OTP: {e}", bootstyle="danger")

# Decrypt Message
def decrypt():
    user_otp = otp_input.get().strip()
    try:
        with open("otp.txt", "r") as f:
            correct_otp = f.read()
    except FileNotFoundError:
        output_label.config(text="OTP not found. Send message first.", bootstyle="danger")
        return

    if user_otp != correct_otp:
        output_label.config(text="Incorrect OTP!", bootstyle="danger")
        return

    try:
        encrypted = load_encrypted()
        key = load_key()
        decrypted = decrypt_message(encrypted, key)
        output_label.config(text=f"Decrypted: {decrypted}", bootstyle="success")
    except Exception as e:
        output_label.config(text=f"Error decrypting: {e}", bootstyle="danger")

# ---------- GUI Setup ----------
style = Style("superhero")
root = style.master
root.title("🔐 Secure Message Encryptor")
root.geometry("500x500")

# Message Input
ttk.Label(root, text="Enter Message:", bootstyle="info").pack(pady=(20, 5))
message_input = tk.Text(root, height=5, width=50)
message_input.pack()

# Phone Number
ttk.Label(root, text="Recipient Phone (e.g. +2547...):", bootstyle="info").pack(pady=(15, 5))
phone_input = ttk.Entry(root, width=40)
phone_input.pack()

# Encrypt & Send OTP Button
ttk.Button(root, text="Encrypt & Send OTP", bootstyle="primary", command=encrypt_and_send).pack(pady=20)

# OTP Input
ttk.Label(root, text="Enter OTP:", bootstyle="info").pack()
otp_input = ttk.Entry(root, width=20)
otp_input.pack()

# Decrypt Button
ttk.Button(root, text="Decrypt Message", bootstyle="success", command=decrypt).pack(pady=20)

# Output Label
output_label = ttk.Label(root, text="", bootstyle="warning")
output_label.pack(pady=10)

# Run the app
root.mainloop()

