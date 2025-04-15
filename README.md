# Secure Password Manager

A simple terminal-based password manager built with Python, SQLite, and the cryptography library.

## Features

-   Add new password entries (website, username/email, password).
-   View all saved passwords (with decryption).
-   Search for a password by website.
-   Delete an entry.
-   Securely encrypts passwords using Fernet encryption.
-   Stores passwords in a local SQLite database.

## Prerequisites

-   Python 3.6+
-   cryptography library: `pip install cryptography`

## Usage

1.  Clone the repository or download the `password_manager.py` file.
2.  Install the required dependencies: `pip install cryptography`
3.  Run the script: `python password_manager.py`
4.  Follow the menu options to manage your passwords.

## Security

-   The password manager uses Fernet encryption to secure your passwords.
-   The encryption key is stored in a file named `key.key`.
-   **Important:** Keep the `key.key` file safe and secure. If you lose it, you will not be able to decrypt your passwords.

## Disclaimer

This password manager is intended for personal use only. Use it at your own risk. The developers are not responsible for any data loss or security breaches.
