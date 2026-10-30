# 🔐 LockSafe — Secure Password Manager






LockSafe is a lightweight, desktop-based password manager built with Python and Tkinter. It uses **AES encryption** to securely store your credentials locally and supports **OTP-based email verification** for account creation and password recovery.

***

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Security Overview](#-security-overview)
- [Known Limitations](#-known-limitations)
- [Future Improvements](#-future-improvements)
- [License](#-license)

***
## Master Password Setup
<img width="432" height="150" alt="image" src="https://github.com/user-attachments/assets/d9b8e7bf-9c0f-4e04-91bb-6ffa30e080ba" />

## Main Dashboard
<img width="990" height="773" alt="image" src="https://github.com/user-attachments/assets/c12fe9ca-354e-4912-b01c-1b110f0d9f01" />

## Saved Passwords
<img width="613" height="525" alt="image" src="https://github.com/user-attachments/assets/699e0dc5-ce2e-4e0f-b92c-1ee770ac8bce" />

## Password Recovery
<img width="266" height="147" alt="image" src="https://github.com/user-attachments/assets/2b9f22c2-0365-4135-89fe-1a909df70715" />


## ✨ Features

- 🔒 **AES Encryption** — All stored passwords are encrypted using AES (MODE_EAX) via `pycryptodome`
- 🧂 **SHA-256 Master Password Hashing** — The master password is hashed with SHA-256 and never stored in plain text
- 📧 **OTP Email Verification** — Account creation and password resets are verified via a 4-digit OTP sent to your registered email
- ⏱️ **OTP Expiry** — OTPs expire after **2 minutes** for added security
- 💪 **Password Strength Checker** — Enforces strong passwords (uppercase, lowercase, digits, special characters, min. 8 chars)
- 👁️ **View Saved Accounts** — Decrypt and view all stored credentials after master password verification
- 🔑 **Forgot Password Recovery** — Users can reset both their account password and master password via OTP

***

## 🛠 Tech Stack

| Component        | Technology              |
|------------------|-------------------------|
| GUI Framework    | Python `tkinter`        |
| Encryption       | `pycryptodome` (AES-EAX)|
| Hashing          | `hashlib` (SHA-256)     |
| Email (OTP)      | `smtplib` (Gmail SMTP)  |
| Storage          | Local plain-text files  |
| Language         | Python 3.7+             |

***

## ✅ Prerequisites

- Python **3.7 or higher**
- A **Gmail account** with an [App Password](https://support.google.com/accounts/answer/185833) enabled (requires 2-Step Verification)
- Windows OS (tested on Windows 10/11)

***

## 📦 Installation

### 1. Clone or Download the Repository

```bash
git clone https://github.com/your-username/locksafe.git
cd locksafe
```

Or download `locksafe.py` directly.

### 2. Install Dependencies

```bash
py -m pip install pycryptodome
```

> ⚠️ Make sure to install `pycryptodome` and **not** the older `pycrypto` package.

### 3. Verify Installation

```bash
py -c "from Crypto.Cipher import AES; print('pycryptodome OK')"
```

***

## ⚙️ Configuration

Before running the app, open `locksafe.py` and fill in your email credentials on **lines 10–11**:

```python
os.environ["SENDER_EMAIL"] = "your_gmail@gmail.com"         # Your Gmail address
os.environ["SENDER_PASSWORD"] = "xxxx xxxx xxxx xxxx"        # Gmail App Password (16 chars)
```

### How to Generate a Gmail App Password

1. Go to your [Google Account](https://myaccount.google.com/)
2. Navigate to **Security** → **2-Step Verification** (must be enabled)
3. Scroll down and click **App passwords**
4. Select app: `Mail`, device: `Windows Computer`
5. Copy the generated 16-character password and paste it into the config

> 🔐 Never use your actual Gmail password — App Passwords are specifically for third-party apps.

***

## 🚀 Usage

### Run the Application

```bash
py locksafe.py
```

### First Launch — Set Master Password

On first launch, you will be prompted to create a **master password**. This password:
- Must be at least 8 characters
- Must contain uppercase, lowercase, a digit, and a special character
- Is stored as a SHA-256 hash in `master_password.txt`

### Core Actions

| Action | Description |
|--------|-------------|
| **Create Account** | Register a new platform credential (requires OTP email verification) |
| **Forgot User Password?** | Reset a saved account's password via OTP |
| **Forgot Master Password?** | Reset the master password via OTP sent to the registered sender email |
| **View Registered Accounts** | Decrypt and display all saved credentials after master password verification |

***

## 📁 Project Structure

```
locksafe/
│
├── locksafe.py              # Main application file
├── master_password.txt      # Stores SHA-256 hash of master password (auto-created)
├── passwords.txt            # Stores encrypted credentials (auto-created)
└── README.md                # This file
```

> ⚠️ **Do not delete or manually edit** `master_password.txt` or `passwords.txt` — this will corrupt your stored credentials.

***

## 🔐 Security Overview

### Encryption
Passwords are encrypted using **AES in EAX mode** (authenticated encryption), which provides both confidentiality and data integrity. The nonce is prepended to the ciphertext and stored together in Base64 format.

```
Stored Format: base64(nonce + ciphertext)
```

### Master Password
The master password is hashed with **SHA-256** before being saved to disk. It is never stored in plain text.

### OTP Verification
A 4-digit OTP is generated using Python's `random.randint()` and sent via Gmail SMTP over TLS. The OTP has a **2-minute expiry window** enforced using `time.time()`.

### ⚠️ Current Security Caveats

> These are known limitations and should be addressed before using this app in production.

- The **encryption key is hardcoded** as `"key123"` — replace this with a securely derived key (e.g., using `PBKDF2` from the master password)
- Credentials are stored in **plain-text files** (`passwords.txt`) — consider using a secure database
- `random.randint()` is **not cryptographically secure** — use `secrets.randbelow()` for OTP generation
- Email credentials are stored as **environment variables in the source file** — use a `.env` file with `python-dotenv` in production

***

## ⚠️ Known Limitations

- Designed for **single-user, local use only**
- No support for **duplicate platforms with different usernames** in the current CSV format
- Password file parsing breaks if a stored value contains a **comma**
- No **clipboard copy** feature for retrieved passwords
- No **search or filter** functionality for saved accounts

***

## 🔮 Future Improvements

- [ ] Derive encryption key from the master password using **PBKDF2/scrypt**
- [ ] Replace plain-text file storage with **SQLite** database
- [ ] Use `secrets` module for **cryptographically secure OTP**
- [ ] Add **copy-to-clipboard** button for each credential
- [ ] Support **search and filter** in the accounts viewer
- [ ] Add `.env` file support for email credentials
- [ ] Add **auto-lock** after inactivity timeout
- [ ] Cross-platform support (macOS/Linux)

***

## 📄 License

This project is licensed under the **MIT License**.  
Feel free to use, modify, and distribute with attribution.

***

## 👤 Author

**Aditya Prakash**  
B.Tech (CSE) | Software Developer  
[GitHub](https://github.com/adityaap11) · [LinkedIn](https://www.linkedin.com/in/aditya-prakash-ap)

***

> © 2025 LockSafe — Your Privacy Matters
