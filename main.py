import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import random
import requests
import os

# --- CONFIGURE THESE FOR INFOBIP ---
INFOBIP_API_KEY = '9e20d79a6156c0c13347f798559edbb4-4a1530a6-de25-4822-999b-18c6c5a7cf08'
INFOBIP_SENDER = 'InfoSMS'
DESTINATION_PHONE = '+254768273937'

# --- UTILS ---

def generate_key():
    key = Fernet.generate_key()
    with open("keys.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("keys.key", "rb").read()

def encrypt_message(message, key):
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    return encrypted

def decrypt_message(encrypted, key):
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode()

def send_otp_infobip(phone, otp):
    url = "https://api.infobip.com/sms/2/text/advanced"
    headers = {
        "Authorization": f"App {INFOBIP_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "messages": [
            {
                "from": INFOBIP_SENDER,
                "destinations": [{"to": phone}],
                "text": f"Your OTP is: {otp}"
            }
        ]
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.status_code, response.text

# --- GUI SETUP ---
root = tk.Tk()
root.title("Secure Message Encryptor")
root.geometry("500x400")
otp_global = ""

def encrypt_action():
    global otp_global
    message = message_input.get("1.0", tk.END).strip()
    if not message:
        messagebox.showwarning("Input Error", "Please enter a message to encrypt.")
        return

    if not os.path.exists("keys.key"):
        generate_key()

    key = load_key()
    encrypted = encrypt_message(message, key)

    with open("encrypted.txt", "wb") as file:
        file.write(encrypted)

    otp_global = str(random.randint(100000, 999999))
    with open("otp.txt", "w") as file:
        file.write(otp_global)

    # Send OTP
    status, res = send_otp_infobip(DESTINATION_PHONE, otp_global)
    if status == 200:
        messagebox.showinfo("Success", "Message encrypted and OTP sent to your phone.")
    else:
        messagebox.showerror("Error", f"Failed to send OTP: {res}")

def decrypt_action():
    otp_entered = otp_entry.get()
    if otp_entered != otp_global:
        messagebox.showerror("Invalid OTP", "The OTP you entered is incorrect.")
        return

    try:
        key = load_key()
        with open("encrypted.txt", "rb") as file:
            encrypted = file.read()
        decrypted = decrypt_message(encrypted, key)
        messagebox.showinfo("Decrypted Message", decrypted)
    except Exception as e:
        messagebox.showerror("Decryption Failed", f"Error: {str(e)}")

# --- GUI WIDGETS ---
tk.Label(root, text="Enter Message to Encrypt:").pack(pady=5)
message_input = tk.Text(root, height=5, width=50)
message_input.pack(pady=5)

tk.Button(root, text="Encrypt & Send OTP", command=encrypt_action).pack(pady=10)

tk.Label(root, text="Enter OTP:").pack()
otp_entry = tk.Entry(root)
otp_entry.pack(pady=5)

tk.Button(root, text="Decrypt Message", command=decrypt_action).pack(pady=20)

root.mainloop()
