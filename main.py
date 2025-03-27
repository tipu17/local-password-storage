import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import cryptography.fernet
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
import secrets
import logging

# --- Constants ---
DATABASE_FILE = 'passwords.db'
PBKDF2_ITERATIONS = 480000
KEY_LENGTH = 32
SALT_LENGTH = 16
MASTER_PASSWORD_HASH_FILE = 'master_password_hash.bin'
ENCRYPTED_KEY_FILE = 'encrypted_key.bin'
SALT_FILE = 'salt.bin'

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# --- Database Functions ---

def create_database():
    """Creates the database and table if they don't exist."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def add_password_to_db(website, username, password, encryption_key):
    """Adds an encrypted password to the database."""
    encrypted_username = encrypt_password(username, encryption_key)
    encrypted_password = encrypt_password(password, encryption_key)

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                       (website, encrypted_username, encrypted_password))
        conn.commit()
        logging.info(f"Password added for {website}")
    except sqlite3.IntegrityError:
        logging.warning(f"Website {website} already exists in the database.")
        messagebox.showerror("Error", f"A password for {website} already exists.")

    finally:
        conn.close()


def get_password_from_db(website, encryption_key):
    """Retrieves and decrypts a password from the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM passwords WHERE website = ?", (website,))
    result = cursor.fetchone()
    conn.close()

    if result:
        encrypted_username, encrypted_password = result
        username = decrypt_password(encrypted_username, encryption_key)
        password = decrypt_password(encrypted_password, encryption_key)

        return username, password
    else:
        return None, None


def update_password_in_db(website, username, password, encryption_key):
    """Updates an existing password in the database."""
    encrypted_username = encrypt_password(username, encryption_key)
    encrypted_password = encrypt_password(password, encryption_key)

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE passwords SET username = ?, password = ? WHERE website = ?",
                   (encrypted_username, encrypted_password, website))
    conn.commit()
    conn.close()
    logging.info(f"Password updated for {website}")

def delete_password_from_db(website):
    """Deletes a password from the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE website = ?", (website,))
    conn.commit()
    conn.close()
    logging.info(f"Password deleted for {website}")


def get_all_websites():
    """Retrieves a list of all website names from the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT website FROM passwords")
    results = cursor.fetchall()
    conn.close()
    return [result[0] for result in results]  # Extract website names from tuples


# --- Crypto Functions ---

def derive_key(password, salt, iterations=PBKDF2_ITERATIONS):
    """Derives a key from the password and salt using PBKDF2."""
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def get_master_password_hash_and_salt():
    """
    Prompts for master password (if first time) or loads existing hash and salt.
    """
    if not os.path.exists(MASTER_PASSWORD_HASH_FILE):
        master_password = input("Set your master password: ")
        if not master_password:
            print("Master password cannot be empty.")
            return None, None

        salt = os.urandom(SALT_LENGTH)
        with open(SALT_FILE, 'wb') as salt_file:
            salt_file.write(salt)

        master_password_hash = derive_key(master_password, salt)
        with open(MASTER_PASSWORD_HASH_FILE, 'wb') as hash_file:
            hash_file.write(master_password_hash)

        return master_password_hash, salt
    else:
        salt = load_salt()
        with open(MASTER_PASSWORD_HASH_FILE, 'rb') as hash_file:
            master_password_hash = hash_file.read()
        return master_password_hash, salt


def verify_master_password(master_password, stored_hash, salt):
    """Verifies the master password against the stored hash."""
    derived_key = derive_key(master_password, salt)
    return secrets.compare_digest(derived_key, stored_hash)


def load_salt():
    """Loads the salt from the salt file."""
    try:
        with open(SALT_FILE, 'rb') as salt_file:
            return salt_file.read()
    except FileNotFoundError:
        logging.error("Salt file not found.")
        return None
    except IOError as e:
        logging.error(f"Error reading salt file: {e}")
        return None


def load_encryption_key(derived_key):
    """Loads or generates the encryption key, encrypting it with derived key."""
    try:
        if not os.path.exists(ENCRYPTED_KEY_FILE):
            encryption_key = cryptography.fernet.Fernet.generate_key()
            f_master = cryptography.fernet.Fernet(derived_key)
            encrypted_encryption_key = f_master.encrypt(encryption_key)
            with open(ENCRYPTED_KEY_FILE, 'wb') as encrypted_key_file:
                encrypted_key_file.write(encrypted_encryption_key)
            return encryption_key
        else:
            with open(ENCRYPTED_KEY_FILE, 'rb') as encrypted_key_file:
                encrypted_encryption_key = encrypted_key_file.read()
            f_master = cryptography.fernet.Fernet(derived_key)
            try:
                encryption_key = f_master.decrypt(encrypted_encryption_key)
                return encryption_key
            except cryptography.fernet.InvalidToken:
                logging.error("Incorrect master password or corrupted key file.")
                messagebox.showerror("Error", "Incorrect master password!")
                return None
    except FileNotFoundError:
        logging.error("Encrypted key file not found.")
        messagebox.showerror("Error", "Encrypted key file not found.")
        return None
    except IOError as e:
        logging.error(f"Error reading/writing encrypted key file: {e}")
        messagebox.showerror("Error", "An error occurred accessing the key file.")
        return None


def encrypt_password(password, encryption_key):
    """Encrypts the given password using the encryption key."""
    f = cryptography.fernet.Fernet(encryption_key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password.decode()


def decrypt_password(encrypted_password, encryption_key):
    """Decrypts the given encrypted password using the encryption key."""
    f = cryptography.fernet.Fernet(encryption_key)
    try:
        decrypted_password = f.decrypt(encrypted_password.encode())
        return decrypted_password.decode()
    except cryptography.fernet.InvalidToken:
        logging.error("Invalid token during password decryption.")
        return None


# --- GUI Functions ---

class PasswordManagerGUI:
    def __init__(self, master, encryption_key):
        self.master = master
        self.master.title("Password Manager")
        self.encryption_key = encryption_key
        self.website_var = tk.StringVar()  # store website name
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.selected_website = None  # Keep track of currently selected website

        # --- Widgets ---
        self.website_label = ttk.Label(master, text="Website:")
        self.website_entry = ttk.Entry(master, textvariable=self.website_var, width=30)
        self.username_label = ttk.Label(master, text="Username:")
        self.username_entry = ttk.Entry(master, textvariable=self.username_var, width=30)
        self.password_label = ttk.Label(master, text="Password:")
        self.password_entry = ttk.Entry(master, textvariable=self.password_var, width=30, show="*")

        self.add_button = ttk.Button(master, text="Add Password", command=self.add_password)
        self.update_button = ttk.Button(master, text="Update Password", command=self.update_password, state=tk.DISABLED) #Initially disabled
        self.delete_button = ttk.Button(master, text="Delete Password", command=self.delete_password, state=tk.DISABLED) #Initially disabled
        self.view_button = ttk.Button(master, text="View Password", command=self.view_password)

        self.website_listbox = tk.Listbox(master, width=40, height=10)
        self.website_listbox.bind('<<ListboxSelect>>', self.on_website_select)  # Bind selection event


        # --- Layout ---
        self.website_label.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.website_entry.grid(row=0, column=1, sticky=tk.E, padx=5, pady=5)
        self.username_label.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry.grid(row=1, column=1, sticky=tk.E, padx=5, pady=5)
        self.password_label.grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_entry.grid(row=2, column=1, sticky=tk.E, padx=5, pady=5)

        self.add_button.grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.update_button.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        self.delete_button.grid(row=3, column=2, sticky=tk.W, padx=5, pady=5)
        self.view_button.grid(row=3, column=3, sticky=tk.W, padx=5, pady=5)

        self.website_listbox.grid(row=4, column=0, columnspan=4, padx=5, pady=5)

        # --- Populate Website List ---
        self.populate_website_list()

    def populate_website_list(self):
        """Populates the website listbox with website names from the database."""
        self.website_listbox.delete(0, tk.END)  # Clear existing list
        websites = get_all_websites()
        for website in websites:
            self.website_listbox.insert(tk.END, website)

    def on_website_select(self, event):
        """Handles the event when a website is selected from the listbox."""
        try:
            index = self.website_listbox.curselection()[0]
            self.selected_website = self.website_listbox.get(index)  # Store selected website

            # Retrieve and populate the entry fields
            username, password = get_password_from_db(self.selected_website, self.encryption_key)
            if username and password:
                self.website_var.set(self.selected_website)
                self.username_var.set(username)
                self.password_var.set(password)
                self.update_button.config(state=tk.NORMAL) #Enable update and delete
                self.delete_button.config(state=tk.NORMAL)
            else:
                messagebox.showerror("Error", f"Could not retrieve password for {self.selected_website}")


        except IndexError:  # No item selected
            pass

    def add_password(self):
        """Adds a new password to the database."""
        website = self.website_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not website or not username or not password:
            messagebox.showerror("Error", "All fields are required.")
            return

        add_password_to_db(website, username, password, self.encryption_key)
        self.clear_fields()
        self.populate_website_list()  # Refresh the list
        self.selected_website = None # Reset selected Website
        self.update_button.config(state=tk.DISABLED) #Disable buttons again.
        self.delete_button.config(state=tk.DISABLED)


    def update_password(self):
      """Updates the password for the selected website."""
      if not self.selected_website:
          messagebox.showerror("Error", "No website selected.")
          return

      website = self.website_var.get().strip()
      username = self.username_var.get().strip()
      password = self.password_var.get().strip()

      if not website or not username or not password:
          messagebox.showerror("Error", "All fields are required.")
          return

      if website != self.selected_website:
          messagebox.showerror("Error", "Cannot change the website name during update.")
          return

      update_password_in_db(website, username, password, self.encryption_key)
      self.clear_fields()
      self.populate_website_list()
      self.selected_website = None #Reset
      self.update_button.config(state=tk.DISABLED) #Disable buttons again.
      self.delete_button.config(state=tk.DISABLED)


    def delete_password(self):
        """Deletes the password for the selected website."""
        if not self.selected_website:
            messagebox.showerror("Error", "No website selected.")
            return

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for {self.selected_website}?"):
            delete_password_from_db(self.selected_website)
            self.clear_fields()
            self.populate_website_list()
            self.selected_website = None # Reset.
            self.update_button.config(state=tk.DISABLED) #Disable buttons again.
            self.delete_button.config(state=tk.DISABLED)


    def view_password(self):
        """Displays the password in a popup window."""
        if not self.selected_website:
            messagebox.showerror("Error", "No website selected.")
            return

        username, password = get_password_from_db(self.selected_website, self.encryption_key)
        if username and password:
            messagebox.showinfo("Password Details",
                                f"Website: {self.selected_website}\nUsername: {username}\nPassword: {password}")
        else:
            messagebox.showerror("Error", f"Could not retrieve password for {self.selected_website}")


    def clear_fields(self):
        """Clears the input fields."""
        self.website_var.set("")
        self.username_var.set("")
        self.password_var.set("")


# --- Main Function ---

def main():
    create_database()  # Ensure the database exists

    master_password_hash, salt = get_master_password_hash_and_salt()
    if master_password_hash is None or salt is None:
        print("Failed to set up or load master password. Exiting.")
        return

    while True:
        master_password_attempt = input("Enter your master password: ")
        if verify_master_password(master_password_attempt, master_password_hash, salt):
            derived_key = derive_key(master_password_attempt, salt)
            encryption_key = load_encryption_key(derived_key)

            if encryption_key:
                break
            else:
                print("Failed to load encryption key. Exiting.")
                return
        else:
            print("Master password incorrect. Please try again.")

    # --- GUI Initialization ---
    root = tk.Tk()
    gui = PasswordManagerGUI(root, encryption_key)
    root.mainloop()


if __name__ == "__main__":
    main()
