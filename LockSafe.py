import hashlib
import random
import smtplib
import re
import os
import tkinter as tk
from tkinter import messagebox, simpledialog
from Crypto.Cipher import AES
import base64

# ---------------------- CONFIG ----------------------
MASTER_PASSWORD_FILE = "master_password.txt"
PASSWORDS_FILE = "passwords.txt"
os.environ["SENDER_EMAIL"] = "noreplylocksafe@gmail.com"
os.environ["SENDER_PASSWORD"] = "tkwc ugyl larn cstk"
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

# ---------------------- CRYPTO ----------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_password(password, key):
    cipher = AES.new(key.ljust(32).encode(), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    return base64.b64encode(cipher.nonce + ciphertext).decode()

def decrypt_password(encrypted_password, key):
    try:
        data = base64.b64decode(encrypted_password)
        nonce, ciphertext = data[:16], data[16:]
        cipher = AES.new(key.ljust(32).encode(), AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(ciphertext).decode()
    except:
        return None

# ---------------------- UTILS ----------------------
def send_otp(email):
    otp = str(random.randint(100000, 999999))
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        message = f"Subject: Password Reset OTP\n\nYour OTP is: {otp}"
        server.sendmail(SENDER_EMAIL, email, message)
        server.quit()
        return otp
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send OTP: {e}")
        return None

def check_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long!"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter!"
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter!"
    if not re.search(r"\d", password):
        return "Password must contain at least one digit!"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character!"
    return "Strong"

# ---------------------- FUNCTIONALITY ----------------------
def create_account():
    platform = entry_platform.get()
    username = entry_username.get()
    email = entry_email.get()
    password = entry_password.get()

    if not platform or not username or not email or not password:
        messagebox.showwarning("Warning", "All fields are required!")
        return

    otp = send_otp(email)
    if not otp:
        return

    user_otp = simpledialog.askstring("OTP Verification", "Enter the OTP sent to your email:")
    if user_otp != otp:
        messagebox.showerror("Error", "Incorrect OTP!")
        return

    encryption_key = "key123"
    encrypted_password = encrypt_password(password, encryption_key)

    with open(PASSWORDS_FILE, "a") as f:
        f.write(f"{platform},{username},{email},{encrypted_password}\n")

    messagebox.showinfo("Success", "Account created successfully!")
    entry_platform.delete(0, tk.END)
    entry_username.delete(0, tk.END)
    entry_email.delete(0, tk.END)
    entry_password.delete(0, tk.END)

def forgot_user_password():
    username = simpledialog.askstring("Forgot Password", "Enter your username:")
    email = None

    with open(PASSWORDS_FILE, "r") as f:
        lines = f.readlines()

    for line in lines:
        try:
            _, user, user_email, _ = line.strip().split(",")
            if user == username:
                email = user_email
                break
        except ValueError:
            continue

    if not email:
        messagebox.showerror("Error", "Username not found!")
        return

    otp = send_otp(email)
    if not otp:
        return

    user_otp = simpledialog.askstring("OTP Verification", "Enter the OTP sent to your email:")
    if user_otp != otp:
        messagebox.showerror("Error", "Incorrect OTP!")
        return

    new_password = simpledialog.askstring("Reset Password", "Enter new password:", show="*")
    encryption_key = "my_secure_key_123"
    encrypted_password = encrypt_password(new_password, encryption_key)

    with open(PASSWORDS_FILE, "w") as f:
        for line in lines:
            try:
                platform, user, user_email, _ = line.strip().split(",")
                if user == username:
                    f.write(f"{platform},{user},{user_email},{encrypted_password}\n")
                else:
                    f.write(line)
            except ValueError:
                continue

    messagebox.showinfo("Success", "Password reset successfully!")

def setup_master_password():
    if not os.path.exists(MASTER_PASSWORD_FILE):
        while True:
            master_password = simpledialog.askstring("Setup Master Password", "Set a master password:", show="*")
            confirm_password = simpledialog.askstring("Confirm Password", "Re-enter the master password:", show="*")

            if not master_password or not confirm_password:
                messagebox.showwarning("Warning", "Password fields cannot be empty!")
                continue

            if master_password != confirm_password:
                messagebox.showerror("Mismatch", "Passwords do not match. Try again.")
                continue

            strength = check_password_strength(master_password)
            if strength != "Strong":
                messagebox.showwarning("Weak Password", strength)
                continue

            with open(MASTER_PASSWORD_FILE, "w") as f:
                f.write(hash_password(master_password))

            messagebox.showinfo("Success", "Master password has been set successfully!")
            break

def forgot_master_password():
    if not os.path.exists(MASTER_PASSWORD_FILE):
        messagebox.showinfo("Info", "Master password is not set yet.")
        return

    recovery_email = simpledialog.askstring("Forgot Master Password", "Enter your registered recovery email:")
    if not recovery_email:
        messagebox.showwarning("Warning", "Email cannot be empty!")
        return

    otp = send_otp(recovery_email)
    if not otp:
        return

    user_otp = simpledialog.askstring("OTP Verification", "Enter the OTP sent to your email:")
    if user_otp != otp:
        messagebox.showerror("Error", "Incorrect OTP!")
        return

    while True:
        new_password = simpledialog.askstring("New Master Password", "Enter a new master password:", show="*")
        confirm_password = simpledialog.askstring("Confirm Password", "Re-enter new master password:", show="*")

        if not new_password or not confirm_password:
            messagebox.showwarning("Warning", "Password fields cannot be empty!")
            continue

        if new_password != confirm_password:
            messagebox.showerror("Mismatch", "Passwords do not match. Try again.")
            continue

        strength = check_password_strength(new_password)
        if strength != "Strong":
            messagebox.showwarning("Weak Password", strength)
            continue

        with open(MASTER_PASSWORD_FILE, "w") as f:
            f.write(hash_password(new_password))

        messagebox.showinfo("Success", "Master password has been reset successfully!")
        break

def verify_master_password():
    if os.path.exists(MASTER_PASSWORD_FILE):
        with open(MASTER_PASSWORD_FILE, "r") as f:
            stored_hash = f.read().strip()
        entered_password = simpledialog.askstring("Verify", "Enter master password:", show="*")
        return hash_password(entered_password) == stored_hash
    return False

def view_saved_passwords():
    if not os.path.exists(PASSWORDS_FILE) or os.stat(PASSWORDS_FILE).st_size == 0:
        messagebox.showinfo("Info", "No saved passwords yet!")
        return

    if not verify_master_password():
        messagebox.showerror("Error", "Incorrect master password!")
        return

    encryption_key = "key123"

    window = tk.Toplevel(root)
    window.title("Saved Passwords")
    window.geometry("500x400")
    window.configure(bg="#49baf3")

    tk.Label(window, text="Saved Accounts", font=("Helvetica", 16, "bold"), bg="#ffffff").pack(pady=10)
    text_area = tk.Text(window, height=20, width=60, font=("Courier", 10), bg="#f9f9f9", relief=tk.FLAT)
    text_area.pack(pady=5)

    with open(PASSWORDS_FILE, "r") as f:
        for line in f:
            try:
                platform, username, email, encrypted_password = line.strip().split(",")
                decrypted_password = decrypt_password(encrypted_password, encryption_key)
                if decrypted_password is None:
                    decrypted_password = "(decryption failed)"
                text_area.insert(tk.END, f"Platform: {platform}\nUsername: {username}\nEmail: {email}\nPassword: {decrypted_password}\n\n")
            except Exception as e:
                text_area.insert(tk.END, f"Error reading entry: {e}\n\n")

# ---------------------- GUI ----------------------
root = tk.Tk()
root.title("LockSafe - Secure Password Manager")
root.geometry("800x600")
root.configure(bg="#ffffff")
root.resizable(False, False)

setup_master_password()

header = tk.Frame(root, bg="#0d47a1", height=60)
header.pack(fill="x")
tk.Label(header, text="🔐 LockSafe", font=("Helvetica", 20, "bold"), fg="white", bg="#0d47a1").pack(pady=10)

form_frame = tk.Frame(root, bg="#ffffff")
form_frame.pack(pady=20)

tk.Label(form_frame, text="Create New Account", font=("Helvetica", 14, "bold"), bg="#ffffff", fg="#333").grid(row=0, columnspan=2, pady=10)

tk.Label(form_frame, text="📱 Platform:", bg="#ffffff").grid(row=1, column=0, sticky="e", padx=10, pady=5)
entry_platform = tk.Entry(form_frame, width=30)
entry_platform.grid(row=1, column=1, padx=10, pady=5)

tk.Label(form_frame, text="👤 Username:", bg="#ffffff").grid(row=2, column=0, sticky="e", padx=10, pady=5)
entry_username = tk.Entry(form_frame, width=30)
entry_username.grid(row=2, column=1, padx=10, pady=5)

tk.Label(form_frame, text="📧 Email:", bg="#ffffff").grid(row=3, column=0, sticky="e", padx=10, pady=5)
entry_email = tk.Entry(form_frame, width=30)
entry_email.grid(row=3, column=1, padx=10, pady=5)

tk.Label(form_frame, text="🔑 Password:", bg="#ffffff").grid(row=4, column=0, sticky="e", padx=10, pady=5)
entry_password = tk.Entry(form_frame, show="*", width=30)
entry_password.grid(row=4, column=1, padx=10, pady=5)

btn_frame = tk.Frame(root, bg="#ffffff")
btn_frame.pack(pady=20)

def styled_button(master, text, command, bg, fg):
    return tk.Button(master, text=text, command=command, width=28, height=2,
                     bg=bg, fg=fg, font=("Helvetica", 10, "bold"), bd=0, relief="ridge", activebackground="#ccc")

styled_button(btn_frame, "Create Account", create_account, "#388e3c", "white").pack(pady=6)
styled_button(btn_frame, "Forgot User Password?", forgot_user_password, "#f57c00", "white").pack(pady=6)
styled_button(btn_frame, "Forgot Master Password?", forgot_master_password, "#9c27b0", "white").pack(pady=6)
styled_button(btn_frame, "View Registered Accounts", view_saved_passwords, "#1976d2", "white").pack(pady=6)

footer = tk.Label(root, text="© 2025 LockSafe - Your Privacy Matters", bg="#ffffff", fg="#888", font=("Arial", 9))
footer.pack(side="bottom", pady=10)

root.mainloop()
