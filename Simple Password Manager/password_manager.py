import os
import sqlite3
from cryptography.fernet import Fernet

# Database setup
DATABASE_FILE = "passwords.db"
KEY_FILE = "key.key"
MASTER_PASSWORD_FILE = "master.key"

def generate_key():
    """Generates a new encryption key."""
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    """Loads the encryption key from the key file."""
    if not os.path.exists(KEY_FILE):
        generate_key()
    return open(KEY_FILE, "rb").read()

def generate_master_password_hash():
    import hashlib
    password = input("Set master password: ").encode('utf-8')
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
    with open(MASTER_PASSWORD_FILE, 'wb') as f:
        f.write(salt + pwdhash)

def verify_master_password() -> bool:
    import hashlib
    if not os.path.exists(MASTER_PASSWORD_FILE):
        generate_master_password_hash()

    with open(MASTER_PASSWORD_FILE, 'rb') as f:
        salt = f.read(16)
        pwdhash = f.read()

    password = input("Enter master password: ").encode('utf-8')
    pwdhash2 = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
    if pwdhash == pwdhash2:
        print("Authentication successful!")
        return True
    else:
        print("Invalid master password!")
        return False
    return open(KEY_FILE, "rb").read()

def encrypt_password(password: str, key: bytes) -> bytes:
    """Encrypts the password using the Fernet key."""
    f = Fernet(key)
    return f.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes, key: bytes) -> str:
    """Decrypts the password using the Fernet key."""
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()

def create_table():
    """Creates the passwords table in the database if it doesn't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def add_password(website: str, username: str, password: str, key: bytes):
    """Adds a new password entry to the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    encrypted_password = encrypt_password(password, key)
    cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                   (website, username, encrypted_password))
    conn.commit()
    conn.close()

def view_passwords(key: bytes):
    """Retrieves and displays all saved passwords."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT website, username, password FROM passwords")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("No passwords saved yet.")
        return

    for row in rows:
        website, username, encrypted_password = row
        password = decrypt_password(encrypted_password, key)
        print(f"Website: {website}, Username: {username}, Password: {password}")

def search_password(website: str, key: bytes):
    """Searches for a password by website."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT website, username, password FROM passwords WHERE website = ?", (website,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        print(f"No password found for website: {website}")
        return

    website, username, encrypted_password = row
    password = decrypt_password(encrypted_password, key)
    print(f"Website: {website}, Username: {username}, Password: {password}")

def delete_password(website: str):
    """Deletes a password entry by website."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE website = ?", (website,))
    conn.commit()
    conn.close()
    print(f"Password for website {website} deleted.")

def main():
    """Main function to run the password manager."""
    create_table()
    key = load_key()
    if not verify_master_password():
        return

    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. View Passwords")
        print("3. Search Password")
        print("4. Delete Password")
        print("5. Exit")

        choice = input("Enter your choice: ")
        if choice not in ["1", "2", "3", "4", "5"]:
            print("Invalid choice. Please try again.")
            continue

        if choice == "1":
            website = input("Enter website: ")
            username = input("Enter username/email: ")
            password = input("Enter password: ")
            add_password(website, username, password, key)
            print("Password added successfully!")
        elif choice == "2":
            view_passwords(key)
        elif choice == "3":
            website = input("Enter website to search for: ")
            search_password(website, key)
        elif choice == "4":
            website = input("Enter website to delete password for: ")
            delete_password(website)
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()