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
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
                UNIQUE (website, username) 
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error during table creation: {e}")
        messagebox.showerror("")
    finally:
        conn.close()


def add_password_to_db(website, username, password, encryption_key):
    """Adds an encrypted password to the database."""
    encrypted_username_db = encrypt_password(username, encryption_key)
    encrypted_password = encrypt_password(password, encryption_key)

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        
        cursor.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                       (website, username, encrypted_password))
        conn.commit()
        logging.info(f"Password added for {website} ({username})")
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"Username '{username}' already exists for website '{website}'.")
        messagebox.showerror("Error", f"The username '{username}' already exists for website '{website}'.")
        return False # Indicate failure
    except sqlite3.Error as e:
        logging.error(f"Database error during insert: {e}")
        messagebox.showerror("Database Error", f"Could not add password: {e}")
        return False # Indicate failure

    finally:
        conn.close()


def get_password_from_db(website, encryption_key):
    """Retrieves and decrypts a password from the database based on website and username."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, password FROM passwords WHERE website = ?", (website,))
        result = cursor.fetchone()
        if result:
            encrypted_password = result[0]
            password = decrypt_password(encrypted_password, encryption_key)
            # Decrypt username retrieved separately if needed, or just return password
            return password # Only need to return password here
        else:
            return None
    except sqlite3.Error as e:
        logging.error(f"Database error during select: {e}")
        messagebox.showerror("Database Error", f"Could not retrieve password: {e}")
        return None
    finally:
        conn.close()

def update_password_in_db(website, username, new_password, encryption_key):
    """Updates an existing password in the database identified by website and username."""
    encrypted_new_password = encrypt_password(new_password, encryption_key)

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE passwords SET password = ? WHERE website = ? AND username = ?",
                       (encrypted_new_password, website, username))
        conn.commit()
        if cursor.rowcount == 0:
             logging.warning(f"No record found to update for {website} ({username})")
             messagebox.showwarning("Update Failed", "No matching record found to update.")
             return False
        logging.info(f"Password updated for {website} ({username})")
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error during update: {e}")
        messagebox.showerror("Database Error", f"Could not update password: {e}")
        return False
    finally:
        conn.close()

def delete_password_from_db(website, username):
    """Deletes a password from the database based on website and username."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM passwords WHERE website = ? AND username = ?", (website, username))
        conn.commit()
        if cursor.rowcount == 0:
             logging.warning(f"No record found to delete for {website} ({username})")
             messagebox.showwarning("Delete Failed", "No matching record found to delete.")
             return False
        logging.info(f"Password deleted for {website} ({username})")
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error during delete: {e}")
        messagebox.showerror("Database Error", f"Could not delete password: {e}")
        return False
    finally:
        conn.close()


def get_all_accounts():
    """Retrieves a list of all website and username combinations from the database."""
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT website, username FROM passwords ORDER BY website, username") # Order for consistency
        results = cursor.fetchall()
        # Format for display: "Website (Username)"
        return [f"{website} ({username})" for website, username in results]
    except sqlite3.Error as e:
        logging.error(f"Database error retrieving accounts: {e}")
        messagebox.showerror("Database Error", f"Could not retrieve account list: {e}")
        return [] # Return empty list on error
    finally:
        conn.close()

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
        if salt is None: return None, None # Handle error from load_salt
        try:
            with open(MASTER_PASSWORD_HASH_FILE, 'rb') as hash_file: master_password_hash = hash_file.read()
            return master_password_hash, salt
        except FileNotFoundError:
             logging.error(f"{MASTER_PASSWORD_HASH_FILE} not found.")
             print(f"Error: {MASTER_PASSWORD_HASH_FILE} not found.")
             return None, None
        except IOError as e:
             logging.error(f"Error reading {MASTER_PASSWORD_HASH_FILE}: {e}")
             print(f"Error reading master password hash file: {e}")
             return None, None


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
        print("Error: Salt file not found. Connot proceed.")
        return None
    except IOError as e:
        logging.error(f"Error reading salt file: {e}")
        print(f"Error reading salt file: {e}")
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
        logging.error(f"Error loading/decrypting encryption key: {e}")
        messagebox.showerror("Key Error", f"Could not load encryption key: {e}")
        return None


def encrypt_password(password, encryption_key):
    """Encrypts the given password using the encryption key."""
    if not isinstance(password_text, str): # Ensure input is string
        password_text = str(password_text)
    f = cryptography.fernet.Fernet(encryption_key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password.decode()


def decrypt_password(encrypted_password_text, encryption_key):
    """Decrypts the given encrypted password using the encryption key."""
    f = cryptography.fernet.Fernet(encryption_key)
    try:
        # Ensure it's bytes before decrypting
        if isinstance(encrypted_password_text, str):
            encrypted_password_bytes = encrypted_password_text.encode()
        else:
             encrypted_password_bytes = encrypted_password_text # Assume it's already bytes if not str

        decrypted_password = f.decrypt(encrypted_password_bytes)
        return decrypted_password.decode()
    except cryptography.fernet.InvalidToken:
        logging.error("Invalid token during password decryption - likely wrong key or corrupted data.")
        # Don't show messagebox here, handle failure in calling function
        return None
    except Exception as e: # Catch other potential errors
        logging.error(f"Error decrypting password: {e}")
        return None


# --- GUI Functions ---

class PasswordManagerGUI:
    def __init__(self, master, encryption_key):
        self.master = master
        self.master.title("Password Manager")
        self.encryption_key = encryption_key
        # --- Tkinter variables ---
        self.website_var = tk.StringVar()  # store website name
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        # --- tracking Selected Item
        self.selected_website = None  # Keep track of currently selected website
        self.selected_username = None # Keep track of currently selected username

        # --- Widgets ---
        # Lables
        ttk.Label(master, text="Website:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(master, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(master, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)

        # Entries
        self.website_entry = ttk.Entry(master, textvariable=self.website_var, width=40)
        self.username_entry = ttk.Entry(master, textvariable=self.username_var, width=40)
        self.password_entry = ttk.Entry(master, textvariable=self.password_var, width=40, show="*")

        self.website_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)
        self.username_entry.grid(row=1, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)
        self.password_entry.grid(row=2, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)

        # Buttons Frame
        button_frame = ttk.Frame(master)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)

        self.add_button = ttk.Button(button_frame, text="Add", command=self.add_password)
        self.update_button = ttk.Button(button_frame, text="Update", command=self.update_password, state=tk.DISABLED)
        self.delete_button = ttk.Button(button_frame, text="Delete", command=self.delete_password, state=tk.DISABLED)
        self.view_button = ttk.Button(button_frame, text="View", command=self.view_password, state=tk.DISABLED) # Disable initially
        self.clear_button = ttk.Button(button_frame, text="Clear Fields", command=self.clear_fields_and_selection)

        self.add_button.pack(side=tk.LEFT, padx=5)
        self.update_button.pack(side=tk.LEFT, padx=5)
        self.delete_button.pack(side=tk.LEFT, padx=5)
        self.view_button.pack(side=tk.LEFT, padx=5)
        self.clear_button.pack(side=tk.LEFT, padx=5)


        # Listbox with Scrollbar
        list_frame = ttk.Frame(master)
        list_frame.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)
        master.grid_rowconfigure(4, weight=1) # Allow listbox frame to expand vertically
        master.grid_columnconfigure(1, weight=1) # Allow entry column to expand horizontally

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        self.account_listbox = tk.Listbox(list_frame, width=50, height=15, yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.account_listbox.yview)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.account_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.account_listbox.bind('<<ListboxSelect>>', self.on_account_select)

        # --- Initial Population ---
        self.populate_account_list()
        
    def populate_account_list(self):
        """Populates the listbox with 'Website (Username)' entries."""
        self.account_listbox.delete(0, tk.END)  # Clear existing list
        accounts = get_all_accounts()
        for account_string in accounts:
            self.account_listbox.insert(tk.END, account_string)
        # After populating, clear selection and disable buttons
        self.clear_fields_and_selection()
        
    def parse_selected_item(self, selected_item_string):
        """Parses 'Website (Username)' string. Handles potential edge cases."""
        # Use regex to capture website and username, robust against parentheses in website name
        match = re.match(r"^(.*)\s+\((.*)\)$", selected_item_string)
        if match:
            website = match.group(1).strip()
            username = match.group(2).strip()
            return website, username
        else:
            # Fallback or error handling if format is unexpected
            logging.warning(f"Could not parse listbox item: {selected_item_string}")
            # As a simple fallback, assume the last parenthesis separates username
            parts = selected_item_string.rsplit('(', 1)
            if len(parts) == 2:
                return parts[0].strip(), parts[1].strip(') ')
            else:
                 return selected_item_string, "" # Or return None, None and handle it

    def on_account_select(self, event):
        """Handles the event when an account is selected from the listbox."""
        if not self.account_listbox.curselection(): # Check if selection exists
            self.clear_fields_and_selection()
            return

        try:
            index = self.account_listbox.curselection()[0]
            selected_item_string = self.account_listbox.get(index)

            website, username = self.parse_selected_item(selected_item_string)

            if website is None: # Parsing failed
                 messagebox.showerror("Error", "Could not parse the selected item.")
                 self.clear_fields_and_selection()
                 return

            self.selected_website = website
            self.selected_username = username

            # Retrieve password (username is already known)
            password = get_password_from_db(self.selected_website, self.selected_username, self.encryption_key)

            if password is not None:
                # Populate the entry fields
                self.website_var.set(self.selected_website)
                self.username_var.set(self.selected_username)
                self.password_var.set(password)

                # Enable relevant buttons
                self.update_button.config(state=tk.NORMAL)
                self.delete_button.config(state=tk.NORMAL)
                self.view_button.config(state=tk.NORMAL)
            else:
                # Handle case where password retrieval failed (e.g., decryption error)
                messagebox.showerror("Error", f"Could not retrieve or decrypt password for {self.selected_website} ({self.selected_username}). The entry might be corrupted.")
                self.clear_fields_and_selection() # Clear fields if retrieval fails


        except IndexError:
            # This shouldn't happen if curselection() is checked, but good practice
            self.clear_fields_and_selection()
        except Exception as e:
             logging.error(f"Error during account selection: {e}")
             messagebox.showerror("Selection Error", f"An error occurred: {e}")
             self.clear_fields_and_selection()

    
    
    

    def add_password(self):
        """Adds a new password entry to the database."""
        website = self.website_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not website or not username or not password:
            messagebox.showerror("Error", "Website, Username, and Password fields are required.")
            return

        if add_password_to_db(website, username, password, self.encryption_key):
             messagebox.showinfo("Success", f"Password for {website} ({username}) added successfully.")
             self.populate_account_list() # Refresh the list includes clearing selection

    def update_password(self):
      """Updates the password for the currently selected account."""
      if not self.selected_website or self.selected_username is None: # Check both
          messagebox.showerror("Error", "No account selected to update.")
          return

      # Get potentially changed password from entry field
      new_password = self.password_var.get().strip()
      # Get website/username from fields - IMPORTANT: compare with selected to prevent accidental changes
      current_website_entry = self.website_var.get().strip()
      current_username_entry = self.username_var.get().strip()


      if not new_password:
           messagebox.showerror("Error", "Password field cannot be empty for update.")
           return

      # Prevent changing the website or username during an update via the fields
      if current_website_entry != self.selected_website or current_username_entry != self.selected_username:
          messagebox.showerror("Update Error", "Cannot change Website or Username during update.\nSelect the correct entry and only modify the Password field.")
          # Optionally, reset fields to selected values
          self.website_var.set(self.selected_website)
          self.username_var.set(self.selected_username)
          return


      if update_password_in_db(self.selected_website, self.selected_username, new_password, self.encryption_key):
          messagebox.showinfo("Success", f"Password for {self.selected_website} ({self.selected_username}) updated.")
          # Optionally clear fields or just keep them populated with updated info
          self.populate_account_list() # Refresh needed if display format changes somehow
          # Re-select the item if desired after update, or just clear selection
          self.clear_fields_and_selection()


    def delete_password(self):
        """Deletes the currently selected account."""
        if not self.selected_website or self.selected_username is None:
            messagebox.showerror("Error", "No account selected to delete.")
            return

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the entry for:\n\nWebsite: {self.selected_website}\nUsername: {self.selected_username}?"):
            if delete_password_from_db(self.selected_website, self.selected_username):
                 messagebox.showinfo("Success", "Account deleted successfully.")
                 self.populate_account_list() # Refresh list includes clearing selection


    def view_password(self):
        """Displays the password for the selected account in a popup."""
        # Check selection status first
        if not self.selected_website or self.selected_username is None:
            messagebox.showerror("Error", "No account selected to view.")
            return

        # Password should already be in the entry field if selection is valid
        password = self.password_var.get() # Get from the entry field directly

        if password: # Should always be true if selection logic worked
            messagebox.showinfo("Password Details",
                                f"Website: {self.selected_website}\n"
                                f"Username: {self.selected_username}\n"
                                f"Password: {password}", # Show password from field
                                parent=self.master) # Make popup modal to main window
        else:
             # This case indicates an issue with selection logic or prior retrieval
             messagebox.showerror("Error", "Could not display password. Please re-select the account.")


    def clear_fields_and_selection(self):
        """Clears the input fields and resets selection state."""
        self.website_var.set("")
        self.username_var.set("")
        self.password_var.set("")
        self.selected_website = None
        self.selected_username = None
        self.account_listbox.selection_clear(0, tk.END) # Clear listbox selection visually
        # Disable buttons that require selection
        self.update_button.config(state=tk.DISABLED)
        self.delete_button.config(state=tk.DISABLED)
        self.view_button.config(state=tk.DISABLED)


# --- Main Function ---

def main():
    create_database()  # Ensure the database exists

    master_password_hash, salt = get_master_password_hash_and_salt()
    if master_password_hash is None or salt is None:
        # Error message already printed in get_master_password_hash_and_salt or load_salt
        return # Exit if setup failed
        
    # --- Master Password Verification Loop ---
    encryption_key = None
    attempts = 0
    max_attempts = 3 # Limit login attempts

    while attempts < max_attempts:
        master_password_attempt = input("Enter your master password (attempt {attempts + 1}/{max_attempts}): ")
        if verify_master_password(master_password_attempt, master_password_hash, salt):
            derived_key = derive_key(master_password_attempt, salt)
            encryption_key = load_encryption_key(derived_key)

            if encryption_key:
                print("Master password verified.")
                break
            else:
                # load_encryption_key failed (likely InvalidToken, file issue handled inside)
                print("Incorrect master password or could not load encryption key.")
                attempts += 1
                # No need to exit here, loop continues
        else:
            print("Master password incorrect. Please try again.")
            attempts += 1
    if not encryption_key:
        print(f"Exceeded maximum login attempts ({max_attempts}). Exiting.")
        return # Exit if login fails after max attempts

    
    # --- GUI Initialization ---
    root = tk.Tk()
    root.geometry("550x450") # Set a reasonable initial size
    app = PasswordManagerGUI(root, encryption_key)
    root.mainloop()


if __name__ == "__main__":
    main()
