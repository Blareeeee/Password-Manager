# Password-Manager
# 🔐 Password Manager

A secure, GUI-based password manager with military-grade encryption and modern GitHub Dark theme interface.

## ✨ Features

### 🔒 Security
- **AES-256 Encryption** using Fernet (cryptography library)
- **PBKDF2 Key Derivation** with 100,000 iterations
- **Master Password Protection** - never stored in plain text
- **Automatic Encrypted Backups** with timestamps
- **Memory Wiping** on logout for sensitive data
- **30-minute Auto-Lock** for inactive sessions

### 🎨 User Interface
- **GitHub Dark Theme** - modern, eye-friendly interface
- **High-DPI Support** - perfect scaling on 4K displays
- **Two-panel Layout** - form on left, password list on right
- **Real-time Search** with instant filtering
- **Context Menu Actions** - right-click for quick operations

### ⚙️ Functionality
- **Secure Password Generator** with customizable complexity
- **One-click Copy** for passwords and usernames
- **Bulk Operations** - delete multiple entries at once
- **Password Visibility Toggle** - show/hide passwords temporarily
- **Notes Field** for additional information
- **Clipboard Integration** with pyperclip

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Tkinter (usually included with Python)
- Git (for cloning)

## Installation

### 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/password-manager.git
cd password-manager

### 2. Create virtual environment (recommended)
python -m venv venv

### 3. Activate virtual environment
On Windows:
venv\Scripts\activate
On Linux/Mac:
source venv/bin/activate

### 4. Install dependencies
pip install -r requirements.txt

### 5. Run the application
python main.py

##📁 File Structure
password-manager/
├── main.py

├── requirements.txt

├── README.md

├── LICENSE

├── .gitignore

└── docs/
    
        └── screenshots/

## Generated Files (not in repo)

passwords.encrypted    # Encrypted password database

salt.bin              # Encryption salt (unique per install)

master.hash           # Hashed master password

backup_*.encrypted    # Automatic timestamped backups


### 🔧 Usage Guide

## Adding a New Password

Enter website/app name in the left panel

Add your username/email

Enter password (or generate one with 🎲 button)

Add optional notes

Click "💾 SAVE"

## Managing Passwords

Search: Type in search box to filter entries

Copy: Click 📋 buttons to copy to clipboard

Edit: Double-click entry or use "✏️ Load" button

Show/Hide: Click 👁️ button to temporarily reveal password

Delete: Select entry and click "🗑️ Delete"

## Password Generation

Click the 🎲 button to generate a secure password:

16 characters minimum

Includes uppercase, lowercase, numbers, symbols

Automatically copied to clipboard

### Linux Specific Setup

## Ubuntu/Debian
sudo apt update
sudo apt install python3-tk

## Fedora
sudo dnf install python3-tkinter

## Arch
sudo pacman -S tk

### ⚠️Disclaimer

This software is provided "as is", without warranty of any kind. The developers are not responsible for any data loss or security breaches. Always keep multiple backups of your encrypted data.
