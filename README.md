# Password Manager

A simple password manager application built with Python, Tkinter for the GUI, and SQLite for data storage. This application allows users to securely store and retrieve their website usernames and passwords.

## Features

*   **Secure Password Storage:** Passwords are encrypted using the `cryptography` library's Fernet module before being stored in the SQLite database.
*   **Master Password Protection:** The encryption key is derived from a master password using PBKDF2, making it difficult for unauthorized users to access the stored passwords.
*   **Graphical User Interface (GUI):** A user-friendly interface built with Tkinter for easy interaction.
*   **Add, Update, and Delete Passwords:** Easily manage your stored passwords with the ability to add new entries, update existing ones, and delete passwords you no longer need.
*   **View Passwords:** Retrieve and view your stored usernames and passwords for specific websites.
*   **Website List:** A listbox displays all saved websites for quick selection.

## Security Considerations

*   **Master Password Security:** The security of this password manager relies heavily on the strength and secrecy of your master password. Choose a strong, unique password and keep it safe.
*   **Master Password Hash Storage:** The hash of the master password is stored locally. While PBKDF2 is used to make brute-force attacks more difficult, it's still crucial to protect the hash file from unauthorized access. **For enhanced security, consider using a system-level key store (e.g., Windows Credential Manager, macOS Keychain, or Linux Secret Service API) to store the master password hash.**
*   **Encryption:** Passwords are encrypted using Fernet, which provides symmetric encryption.
*   **Disclaimer:** This application is provided as-is and is intended for educational purposes. It is essential to understand the security implications before using it to store sensitive data.  Consult with security experts for a comprehensive security assessment.

## Prerequisites

*   **Python 3.6 or higher:**  Make sure you have Python installed on your system.
*   **`cryptography` library:** Install the required library using pip:

    ```bash
    pip install cryptography
    ```

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/password-manager.git
    cd password-manager
    ```

2.  **Create a virtual environment (recommended):**

    ```bash
    python -m venv myenv
    ```

3.  **Activate the virtual environment:**

    *   **Linux/macOS:**

        ```bash
        source myenv/bin/activate
        ```

    *   **Windows (Command Prompt):**

        ```cmd
        myenv\Scripts\activate.bat
        ```

    *   **Windows (PowerShell):**

        ```powershell
        myenv\Scripts\Activate.ps1
        ```

4.  **Install the `cryptography` library (if not already installed):**

    ```bash
    pip install cryptography
    ```

## Usage

1.  **Run the script:**

    ```bash
    python your_script_name.py  # Replace your_script_name.py with the actual filename
    ```

2.  **Set a Master Password:** The first time you run the application, you will be prompted to set a master password. Choose a strong and memorable password.

3.  **Use the GUI:** The GUI will appear, allowing you to add, update, delete, and view your stored passwords.

## File Descriptions

*   `main.py`: The main Python script containing the password manager logic and GUI.
*   `passwords.db`: The SQLite database file where encrypted passwords are stored.
*   `master_password_hash.bin`:  File storing the PBKDF2 hash of the master password.
*   `encrypted_key.bin`: File storing the encryption key, encrypted with the derived key from the master password.
*   `salt.bin`: File storing the salt used in the PBKDF2 key derivation function.
*   `README.md`: This file.


## Disclaimer

This password manager is provided as-is and is intended for educational purposes.
The author is not responsible for any data loss or security breaches that may occur as a result of using this application.
Use at your own risk.
**It is strongly recommended to consult with security professionals for a comprehensive security assessment before using this application to store sensitive data.**
