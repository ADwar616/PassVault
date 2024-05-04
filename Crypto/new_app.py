from cryptography.fernet import Fernet
import json
import csv
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from AES_VL import encrypt_AES, decrypt_AES, derive_key_from_password, stealth_mode_encrypt_AES, stealth_mode_decrypt_AES

class PasswordManager:
    def __init__(self, key_file="key.key", data_file="passwords.json"):
        self.key_file = key_file
        self.data_file = data_file
        self.master_password = None
        self.failed_login_attempts = 0
        self.load_key()
        self.load_master_password()

    def load_key(self):
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)
        else:
            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
        self.cipher_suite = Fernet(key)

    def load_master_password(self):
        self.master_password = "secure11"

    def verify_master_password(self, input_password):
        if input_password == self.master_password:
            self.failed_login_attempts = 0
            return True
        else:
            self.failed_login_attempts += 1
            return False

    def encrypt_data(self, data):
        if self.failed_login_attempts >= 5:
            return stealth_mode_encrypt_AES(data.encode())
        else:
            key = derive_key_from_password(self.master_password.encode())
            return encrypt_AES(data.encode(), key)

    def decrypt_data(self, encrypted_data):
        if self.failed_login_attempts >= 5:
            decrypted_data = stealth_mode_decrypt_AES(encrypted_data)
        else:
            key = derive_key_from_password(self.master_password.encode())
            decrypted_data = decrypt_AES(encrypted_data, key)
        return decrypted_data
        

    def load_passwords(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, "rb") as file:
                encrypted_data = file.read()
            decrypted_data = self.decrypt_data(encrypted_data)
            try:
                return json.loads(decrypted_data.decode())
            except UnicodeDecodeError:
                messagebox.showerror("Error", "Invalid password data. Please reset the application.")
                return {}
        return {}

    def save_passwords(self, passwords):
        data = json.dumps(passwords)
        encrypted_data = self.encrypt_data(data)
        with open(self.data_file, "wb") as file:
            file.write(encrypted_data)

    def add_password(self, website, username, password):
        passwords = self.load_passwords()
        passwords[website] = {"username": username, "password": password}
        self.save_passwords(passwords)

    def get_password(self, website):
        passwords = self.load_passwords()
        return passwords.get(website, None)

    def display_passwords(self):
        passwords = self.load_passwords()
        if passwords:
            return [(website, data['username'], data['password']) for website, data in passwords.items()]
        return []
    
    def save_passwords_to_csv(self, passwords):
        with open('encrypted_passwords.csv', 'w', newline='') as csvfile:
            fieldnames = ['Website', 'Encrypted Password']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for website, data in passwords.items():
                encrypted_password = self.encrypt_data(data['password'].encode())
                writer.writerow({'Website': website, 'Encrypted Password': encrypted_password})
    
class LoginWindow(tk.Toplevel):
    def __init__(self, password_manager, on_login_success):
        super().__init__()
        self.title("Login")
        self.password_manager = password_manager
        self.on_login_success = on_login_success
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Enter Master Password:", font=("Helvetica", 14)).pack(pady=10)
        self.password_entry = ttk.Entry(self, show="*", font=("Helvetica", 12))
        self.password_entry.pack(pady=10)
        ttk.Button(self, text="Login", command=self.login, style="TButton").pack()

    def login(self):
        entered_password = self.password_entry.get()
        if self.password_manager.verify_master_password(entered_password):
            self.on_login_success()
            self.destroy()
        else:
            messagebox.showerror("Login Failed", "Incorrect master password. Please try again.")
            self.password_entry.delete(0, tk.END)

class UIManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("{0}x{1}+0+0".format(root.winfo_screenwidth(), root.winfo_screenheight()))
        self.password_manager = PasswordManager()
        self.login_window = None
        self.logged_in = False

        # Create main frame
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky="nsew")

        # Style settings
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Helvetica", 12))

        # Display menu
        self.display_menu()

    def display_menu(self):
        ttk.Label(self.main_frame, text="PassVault", font=("Helvetica", 24, "bold")).grid(row=0, column=0, pady=20)
        ttk.Button(self.main_frame, text="Add Password", command=self.add_password, style="TButton").grid(row=1, column=0, pady=10)
        ttk.Button(self.main_frame, text="Get Password", command=self.get_password, style="TButton").grid(row=2, column=0, pady=10)
        ttk.Button(self.main_frame, text="Display Passwords", command=self.display_passwords, style="TButton").grid(row=3, column=0, pady=10)

    def add_password(self):
        self.check_login()
        add_password_window = tk.Toplevel(self.root)
        add_password_window.title("Add Password")

        ttk.Label(add_password_window, text="Enter website:", font=("Helvetica", 14)).grid(row=0, column=0, padx=10, pady=5)
        website_entry = ttk.Entry(add_password_window, font=("Helvetica", 12))
        website_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(add_password_window, text="Enter username:", font=("Helvetica", 14)).grid(row=1, column=0, padx=10, pady=5)
        username_entry = ttk.Entry(add_password_window, font=("Helvetica", 12))
        username_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(add_password_window, text="Enter password:", font=("Helvetica", 14)).grid(row=2, column=0, padx=10, pady=5)
        password_entry = ttk.Entry(add_password_window, show="*", font=("Helvetica", 12))
        password_entry.grid(row=2, column=1, padx=10, pady=5)

        ttk.Button(add_password_window, text="Save Password", command=lambda: self.save_password(
            website_entry.get(), username_entry.get(), password_entry.get())).grid(row=3, column=0, columnspan=2, pady=10, padx=10)

    def check_login(self):
        # Ensure the user is logged in before accessing features
        if not self.logged_in:
            if self.password_manager.failed_login_attempts >= 5:
                self.show_max_attempts_message()
            else:
                self.login_window = LoginWindow(self.password_manager, self.on_login_success)
                self.login_window.wait_window()

    def show_max_attempts_message(self):
        messagebox.showinfo("Maximum Attempts Reached", "Maximum login attempts reached. All passwords have been encrypted in stealth mode.")
        # Save passwords to CSV before closing the application
        passwords = self.password_manager.load_passwords()
        self.password_manager.save_passwords_to_csv(passwords)
        self.root.destroy()

    def on_login_success(self):
        self.logged_in = True

    def save_password(self, website, username, password):
        self.password_manager.add_password(website, username, password)
        messagebox.showinfo("Success", "Password added successfully!")

    def get_password(self):
        self.check_login()
        get_password_window = tk.Toplevel(self.root)
        get_password_window.title("Get Password")

        ttk.Label(get_password_window, text="Enter website:", font=("Helvetica", 14)).grid(row=0, column=0, padx=10, pady=5)
        website_entry = ttk.Entry(get_password_window, font=("Helvetica", 12))
        website_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Button(get_password_window, text="Get Password", command=lambda: self.show_password(
            website_entry.get())).grid(row=1, column=0, columnspan=2, pady=10)

    def show_password(self, website):
        stored_password = self.password_manager.get_password(website)
        if stored_password:
            messagebox.showinfo("Password Details", f"Username: {stored_password['username']}, Password: {stored_password['password']}")
        else:
            messagebox.showinfo("Password Not Found", "Password not found for the given website.")

    def display_passwords(self):
        self.check_login()
        display_passwords_window = tk.Toplevel(self.root)
        display_passwords_window.title("Display Passwords")

        passwords = self.password_manager.display_passwords()
        if passwords:
            for i, (website, username, password) in enumerate(passwords, start=1):
                ttk.Label(display_passwords_window, text=f"Website: {website}, Username: {username}, Password: {password}", font=("Helvetica", 12)).grid(row=i, column=0, padx=10, pady=5)
        else:
            ttk.Label(display_passwords_window, text="No passwords stored.", font=("Helvetica", 14)).grid(row=1, column=0, padx=10, pady=5)

# Create the main application window
root = tk.Tk()
app = UIManager(root)
root.mainloop()
