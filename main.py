import json
import os
import hashlib
import secrets
import hmac
import string
import re
import customtkinter as ctk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
import time # Used for clipboard timeout

# ===================== CONFIG =====================
vault_file = "vault.json"
key_file = "key.key"
iterations = 100_000
WINDOW_WIDTH = 800
WINDOW_HEIGHT = 600

# ===================== ENCRYPTION =====================
def load_key():
    """Loads the encryption key or generates a new one."""
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

# Initialize Fernet with the loaded/generated key
fernet = Fernet(load_key())

# ===================== VAULT =====================
def load_vault():
    """Loads and decrypts the vault content."""
    if not os.path.exists(vault_file):
        return []
    try:
        with open(vault_file, "rb") as f:
            data = f.read()
            if not data:
                return []
            decrypted = fernet.decrypt(data)
            return json.loads(decrypted)
    except Exception as e:
        messagebox.showerror("Vault Error", f"Could not load or decrypt vault. The file might be corrupted. Error: {e}")
        return []

def save_vault(vault):
    """Encrypts and saves the vault content."""
    try:
        with open(vault_file, "wb") as f:
            data = json.dumps(vault, indent=4).encode()
            encrypted = fernet.encrypt(data)
            f.write(encrypted)
    except Exception as e:
        messagebox.showerror("Save Error", f"Could not save or encrypt vault. Error: {e}")

# ===================== PASSWORD UTILITIES =====================
def hash_password(password):
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()
    return {"salt": salt.hex(), "hash": hashed, "iterations": iterations}

def verify_password(password, stored):
    """Verifies a password against a stored hash."""
    salt = bytes.fromhex(stored["salt"])
    stored_hash = stored["hash"]
    iter_count = stored["iterations"]
    new_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iter_count).hex()
    return hmac.compare_digest(new_hash, stored_hash)

def generate_password(length=16):
    """Generates a strong, random password."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def is_strong_password(password):
    """Checks if a password meets complexity requirements."""
    if len(password) < 12: return False # Increased minimum length for better security
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"\d", password): return False
    if not re.search(r"[!@#$%^&*()?,.\"':{}|<>]", password): return False
    return True

# ===================== APP =====================
class PasswordManagerApp:
    def __init__(self, root):
        """Initializes the application, sets up the window, and loads the vault."""
        self.root = root
        self.root.title("Offline Password Manager")
        self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.root.resizable(False, False)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.vault = load_vault()
        self.current_user = None
        self.login_window()

    # ---------------- LOGIN/SIGNUP ----------------
    def login_window(self):
        """Displays the login screen."""
        self.clear_window()
        self.root.title("Offline Password Manager - Login")
        self.login_frame = ctk.CTkFrame(self.root, corner_radius=10)
        self.login_frame.pack(expand=True, padx=40, pady=40)

        ctk.CTkLabel(self.login_frame, text="Master Username", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        self.username_entry = ctk.CTkEntry(self.login_frame, font=ctk.CTkFont(size=14), width=250)
        self.username_entry.pack(pady=5)

        ctk.CTkLabel(self.login_frame, text="Master Password", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        self.password_entry = ctk.CTkEntry(self.login_frame, font=ctk.CTkFont(size=14), show="*", width=250)
        self.password_entry.pack(pady=5)

        ctk.CTkButton(self.login_frame, text="Login", width=200, command=self.login).pack(pady=20)
        ctk.CTkButton(self.login_frame, text="Sign Up", width=200, command=self.signup_window).pack()

    def signup_window(self):
        """Displays the signup screen."""
        self.clear_window()
        self.root.title("Offline Password Manager - Sign Up")
        self.signup_frame = ctk.CTkFrame(self.root, corner_radius=10)
        self.signup_frame.pack(expand=True, padx=40, pady=40)

        ctk.CTkLabel(self.signup_frame, text="New Master Username", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        self.new_username = ctk.CTkEntry(self.signup_frame, font=ctk.CTkFont(size=14), width=250)
        self.new_username.pack(pady=5)

        ctk.CTkLabel(self.signup_frame, text="New Master Password", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        self.new_password = ctk.CTkEntry(self.signup_frame, font=ctk.CTkFont(size=14), show="*", width=250)
        self.new_password.pack(pady=5)

        ctk.CTkButton(self.signup_frame, text="Register", width=200, command=self.signup).pack(pady=20)
        ctk.CTkButton(self.signup_frame, text="Back to Login", width=200, command=self.login_window).pack()

    def login(self):
        """Attempts to log the user in."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        for user in self.vault:
            if user["username"] == username:
                if verify_password(password, user["password"]):
                    self.current_user = user
                    messagebox.showinfo("Login", f"Welcome, {username}!")
                    self.main_window()
                else:
                    messagebox.showerror("Error", "Invalid Password!")
                return
        messagebox.showerror("Error", "Username not found!")

    def signup(self):
        """Attempts to register a new user."""
        username = self.new_username.get()
        password = self.new_password.get()

        if not username or not password:
            messagebox.showwarning("Warning", "Username and password cannot be empty.")
            return

        if any(u["username"] == username for u in self.vault):
            messagebox.showerror("Error", "Username already exists!")
            return

        if not is_strong_password(password):
            messagebox.showwarning("Weak Master Password",
                                   "Master Password must be at least 12 chars and include uppercase, lowercase, digit, and special character.")
            return

        self.vault.append({
            "username": username,
            "password": hash_password(password),
            "accounts": []
        })
        save_vault(self.vault)
        messagebox.showinfo("Success", "Signup Successful! Please log in.")
        self.login_window()

    # ---------------- MAIN WINDOW ----------------
    def main_window(self):
        """Displays the main application window with tabs."""
        self.clear_window()
        self.root.title(f"Offline Password Manager - {self.current_user['username']}")

        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)

        self.tabs = ctk.CTkTabview(main_frame, width=WINDOW_WIDTH - 40, height=WINDOW_HEIGHT - 100)
        self.tabs.pack(pady=10, padx=10, expand=True, fill="both")

        self.tabs.add("Add Account")
        self.tabs.add("Accounts")

        self.build_add_tab()
        self.build_view_tab()

        ctk.CTkButton(main_frame, text="Logout", command=self.logout, fg_color="red", hover_color="#8b0000").pack(pady=5)

    # ---------------- ADD ACCOUNT TAB ----------------
    def build_add_tab(self):
        """Builds the UI for the Add Account tab."""
        frame = self.tabs.tab("Add Account")
        frame.columnconfigure(1, weight=1)

        labels = ["Site Name:", "Site Username:", "Category/Tag:", "Password:"]
        self.entries = {}

        for i, text in enumerate(labels):
            ctk.CTkLabel(frame, text=text, font=ctk.CTkFont(size=14)).grid(row=i, column=0, sticky="w", padx=10, pady=10)
            entry = ctk.CTkEntry(frame, font=ctk.CTkFont(size=14), width=300)
            entry.grid(row=i, column=1, sticky="ew", padx=10, pady=10)
            self.entries[text] = entry

        # Special handling for password entry to enable show="*"
        self.password_entry_add = self.entries["Password:"]
        self.password_entry_add.configure(show="*")

        # Buttons
        button_frame = ctk.CTkFrame(frame, fg_color="transparent")
        button_frame.grid(row=4, column=0, columnspan=2, pady=20)
        ctk.CTkButton(button_frame, text="Generate Strong Password", command=self.generate_password_add, width=200).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="Add Account", command=self.add_account, width=200).pack(side="left", padx=10)

    def generate_password_add(self):
        """Generates a password and inserts it into the entry field."""
        pwd = generate_password(24) # Generate longer password
        self.password_entry_add.delete(0, ctk.END)
        self.password_entry_add.insert(0, pwd)
        messagebox.showinfo("Generated Password", f"A strong password has been generated and placed in the field.")

    def add_account(self):
        """Adds a new account entry to the vault."""
        site = self.entries["Site Name:"].get().strip()
        site_user = self.entries["Site Username:"].get().strip()
        category = self.entries["Category/Tag:"].get().strip() or "General"
        site_pass = self.password_entry_add.get()

        if not site or not site_user or not site_pass:
            messagebox.showwarning("Missing Data", "Site Name, Username, and Password are required.")
            return

        if not is_strong_password(site_pass):
            messagebox.showwarning("Weak Password",
                                   "The site password must be strong (min 12 chars, uppercase, lowercase, digit, and special character).")
            # Offer to generate a new one
            if messagebox.askyesno("Generate?", "Do you want to generate a strong password instead?"):
                 self.generate_password_add()
                 return
            return

        try:
            encrypted_pass = fernet.encrypt(site_pass.encode()).decode()
            self.current_user["accounts"].append({
                "site": site,
                "site_username": site_user,
                "site_password": encrypted_pass,
                "category": category
            })
            save_vault(self.vault)
            messagebox.showinfo("Success", "Account added successfully!")

            # Clear entries
            for entry in self.entries.values():
                entry.delete(0, ctk.END)

            # Refresh the view tab immediately
            self.refresh_accounts_tree()

        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt and save account: {e}")


    # ---------------- VIEW/SEARCH TAB ----------------
    def build_view_tab(self):
        """Builds the UI for the View/Accounts tab."""
        frame = self.tabs.tab("Accounts")
        frame.columnconfigure(0, weight=1)

        search_frame = ctk.CTkFrame(frame, fg_color="transparent")
        search_frame.pack(fill="x", padx=10, pady=10)
        search_frame.columnconfigure(0, weight=1)

        ctk.CTkLabel(search_frame, text="Search (Site, Username, or Category):", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, sticky="w")
        self.search_entry = ctk.CTkEntry(search_frame, font=ctk.CTkFont(size=14), width=300)
        self.search_entry.grid(row=1, column=0, sticky="ew", padx=(0, 10))
        self.search_entry.bind('<KeyRelease>', lambda event: self.search_accounts()) # Live search

        ctk.CTkButton(search_frame, text="Search", command=self.search_accounts).grid(row=1, column=1, padx=(0, 10))

        # Scrollable frame for displaying accounts
        self.accounts_tree = ctk.CTkScrollableFrame(frame, label_text="Your Encrypted Accounts", label_font=ctk.CTkFont(size=16, weight="bold"))
        self.accounts_tree.pack(expand=True, fill="both", padx=10, pady=10)
        self.accounts_tree.columnconfigure(0, weight=1)

        # Action Buttons
        button_frame = ctk.CTkFrame(frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(button_frame, text="Reveal Password (1st Match)", command=self.reveal_password).pack(side="left", padx=10, expand=True)
        ctk.CTkButton(button_frame, text="Copy Password (1st Match)", command=self.copy_password).pack(side="left", padx=10, expand=True)

        self.refresh_accounts_tree()

    def refresh_accounts_tree(self, accounts=None):
        """Refreshes the display of accounts in the scrollable frame."""
        for widget in self.accounts_tree.winfo_children():
            widget.destroy()

        # Get accounts to display, defaults to all user accounts
        accounts_to_display = accounts if accounts is not None else self.current_user["accounts"]

        if not accounts_to_display:
            ctk.CTkLabel(self.accounts_tree, text="No accounts found.", text_color="gray").pack(pady=20)
            return

        for i, acc in enumerate(accounts_to_display):
            frame = ctk.CTkFrame(self.accounts_tree, corner_radius=5, fg_color="#333", border_width=1, border_color="#555")
            frame.grid(row=i, column=0, sticky="ew", pady=4, padx=5)

            # Display key info
            text = (f"🔑 Site: {acc['site']}\n"
                    f"👤 Username: {acc['site_username']}\n"
                    f"🏷️ Category: {acc.get('category','General')}\n"
                    f"🔒 Password: {'*' * 16} (Encrypted)")

            ctk.CTkLabel(frame, text=text, font=ctk.CTkFont(size=13, weight="normal"), justify="left", wraplength=700).pack(anchor="w", padx=10, pady=5)


    def search_accounts(self):
        """Filters accounts based on the search keyword and updates the display."""
        keyword = self.search_entry.get().lower().strip()

        if not keyword:
            self.refresh_accounts_tree(self.current_user["accounts"])
            return

        filtered = [acc for acc in self.current_user["accounts"]
                    if keyword in acc["site"].lower() or
                       keyword in acc["site_username"].lower() or
                       (acc.get("category") and keyword in acc["category"].lower())]

        self.refresh_accounts_tree(filtered)

    def _get_first_matching_account(self):
        """Helper to get the first account matching the current search keyword."""
        keyword = self.search_entry.get().lower().strip()
        if not keyword:
            return None

        for acc in self.current_user["accounts"]:
            if keyword in acc["site"].lower() or keyword in acc["site_username"].lower() or (acc.get("category") and keyword in acc["category"].lower()):
                return acc
        return None

    def reveal_password(self):
        """Decrypts and reveals the password of the first matching account."""
        selected = self._get_first_matching_account()
        if selected:
            try:
                decrypted_pass = fernet.decrypt(selected["site_password"].encode()).decode()
                messagebox.showinfo(f"Password for {selected['site']}", f"Password: \n{decrypted_pass}")
            except Exception as e:
                messagebox.showerror("Decryption Error", f"Could not decrypt password. Error: {e}")
        else:
            messagebox.showwarning("Warning", "No account matches the search keyword for revealing.")

    def copy_password(self):
        """Decrypts and copies the password of the first matching account to clipboard."""
        selected = self._get_first_matching_account()
        if selected:
            try:
                decrypted_pass = fernet.decrypt(selected["site_password"].encode()).decode()

                # Copy to clipboard
                self.root.clipboard_clear()
                self.root.clipboard_append(decrypted_pass)

                # Optional: Clear clipboard after a short time for security
                self.root.after(30000, self.root.clipboard_clear) # Clears after 30 seconds

                messagebox.showinfo("Copied", "Password copied to clipboard and will be cleared automatically in 30 seconds!")
            except Exception as e:
                messagebox.showerror("Copy Error", f"Could not decrypt or copy password. Error: {e}")
        else:
            messagebox.showwarning("Warning", "No account matches the search keyword for copying.")

    # ---------------- UTIL ----------------
    def clear_window(self):
        """Destroys all widgets in the main window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def logout(self):
        """Saves the vault and returns to the login screen."""
        save_vault(self.vault)
        self.current_user = None
        messagebox.showinfo("Logout", "Vault saved. You have been logged out.")
        self.login_window()

# ===================== RUN APP =====================
if __name__ == "__main__":
    root = ctk.CTk()
    app = PasswordManagerApp(root)
    root.mainloop()