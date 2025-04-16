#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import getpass
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptedPasswordManager:
    def __init__(self, file_path="encrypted_passwords.json"):
        """Initialize the password manager with a file path.

        Args:
            file_path: Path to the encrypted JSON file to store passwords
        """
        self.file_path = file_path
        self.key = None
        self.passwords = {}
        self.salt = None
        
    def _derive_key(self, master_password, salt=None):
        """Derive an encryption key from the master password and salt."""
        if salt is None:
            salt = os.urandom(16)  # Generate a new salt if not provided
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key, salt
    
    def _get_master_password(self):
        """Prompt for the master password."""
        return getpass.getpass("Enter master password: ")
        
    def create_vault(self):
        """Create a new password vault with a master password."""
        if os.path.exists(self.file_path):
            print("Password vault already exists. Use load_vault instead.")
            return False
            
        master_password = self._get_master_password()
        confirm_password = getpass.getpass("Confirm master password: ")
        
        if master_password != confirm_password:
            print("Passwords do not match.")
            return False
            
        self.key, self.salt = self._derive_key(master_password)
        self.passwords = {}
        
        # Save empty vault with salt
        self._save_encrypted_data()
        print("New password vault created successfully.")
        return True
        
    def load_vault(self):
        """Load the password vault using the master password."""
        if not os.path.exists(self.file_path):
            print("Password vault does not exist. Use create_vault first.")
            return False
            
        # First load the file to get the salt
        try:
            with open(self.file_path, 'r') as file:
                data = json.load(file)
                self.salt = base64.b64decode(data["salt"])
        except Exception as e:
            print("Error loading password vault: {}".format(str(e)))
            return False
            
        # Now derive the key with the salt
        master_password = self._get_master_password()
        self.key, _ = self._derive_key(master_password, self.salt)
        
        # Try to decrypt
        try:
            self._load_encrypted_data()
            print("Password vault loaded successfully.")
            return True
        except Exception as e:
            print("Wrong password or corrupted file: {}".format(str(e)))
            self.key = None
            self.salt = None
            self.passwords = {}
            return False
            
    def _ensure_key_loaded(self):
        """Ensure the encryption key is loaded."""
        if self.key is None:
            raise ValueError("No vault is loaded. Create or load a vault first.")
            
    def _encrypt_data(self, data):
        """Encrypt the JSON data."""
        self._ensure_key_loaded()
        fernet = Fernet(self.key)
        json_data = json.dumps(data).encode()
        return fernet.encrypt(json_data)
        
    def _decrypt_data(self, encrypted_data):
        """Decrypt the JSON data."""
        self._ensure_key_loaded()
        fernet = Fernet(self.key)
        json_data = fernet.decrypt(encrypted_data).decode()
        return json.loads(json_data)
        
    def _save_encrypted_data(self):
        """Save the encrypted passwords to file."""
        self._ensure_key_loaded()
        
        try:
            encrypted_data = self._encrypt_data(self.passwords)
            
            with open(self.file_path, 'w') as file:
                data = {
                    "salt": base64.b64encode(self.salt).decode(),
                    "data": encrypted_data.decode()
                }
                json.dump(data, file)
                
            return True
        except Exception as e:
            print("Error saving passwords: {}".format(str(e)))
            return False
            
    def _load_encrypted_data(self):
        """Load the encrypted passwords from file."""
        self._ensure_key_loaded()
        
        try:
            with open(self.file_path, 'r') as file:
                data = json.load(file)
                self.salt = base64.b64decode(data["salt"])
                self.passwords = self._decrypt_data(data["data"].encode())
                
            return True
        except Exception as e:
            raise ValueError("Could not decrypt data: {}".format(str(e)))
            
    def create_login(self, website, user, pwd):
        """Create a new login entry.

        Args:
            website: Website or app name
            user: Username
            pwd: Password

        Returns:
            Boolean indicating success
        """
        self._ensure_key_loaded()
        
        if not website or not user or not pwd:
            print("Website/app name, username, and password are required")
            return False

        # Check if website already exists
        if website in self.passwords:
            print("Entry for {} already exists. Use update_login instead".format(website))
            return False

        # Create new entry
        self.passwords[website] = [
            {
                "user": user,
                "pwd": pwd,
                "current": True
            }
        ]

        return self._save_encrypted_data()

    def update_login(self, website, updates):
        """Update an existing login.

        Args:
            website: Website or app name
            updates: Dictionary with 'user' and/or 'pwd' keys for updates

        Returns:
            Boolean indicating success
        """
        self._ensure_key_loaded()
        
        if not website or not updates:
            print("Website/app name and update information are required")
            return False

        # Check if website exists
        if website not in self.passwords:
            print("No entry found for {}".format(website))
            return False

        # Get current entries and mark them as not current
        entries = self.passwords[website]
        for entry in entries:
            if entry["current"]:
                entry["current"] = False

        # Create new entry with updated information
        last_entry = entries[-1]
        new_entry = {
            "user": updates.get("user", last_entry["user"]),
            "pwd": updates.get("pwd", last_entry["pwd"]),
            "current": True
        }

        # Add new entry
        entries.append(new_entry)

        return self._save_encrypted_data()

    def get_current_user(self, website):
        """Get current username for a website/app.

        Args:
            website: Website or app name to look up

        Returns:
            Current username or None if not found
        """
        self._ensure_key_loaded()
        
        if not website or website not in self.passwords:
            print("No entry found for {}".format(website))
            return None

        entries = self.passwords[website]
        for entry in entries:
            if entry["current"]:
                return entry["user"]
        return None

    def get_current_pwd(self, website):
        """Get current password for a website/app.

        Args:
            website: Website or app name to look up

        Returns:
            Current password or None if not found
        """
        self._ensure_key_loaded()
        
        if not website or website not in self.passwords:
            print("No entry found for {}".format(website))
            return None

        entries = self.passwords[website]
        for entry in entries:
            if entry["current"]:
                return entry["pwd"]
        return None

    def list_websites(self):
        """List all websites/apps in the password manager.

        Returns:
            List of website/app names
        """
        self._ensure_key_loaded()
        return list(self.passwords.keys())

    def get_website_history(self, website):
        """Get all entries for a specific website/app (including history).

        Args:
            website: Website or app name to look up

        Returns:
            List of entries or None if not found
        """
        self._ensure_key_loaded()
        
        if not website or website not in self.passwords:
            print("No entry found for {}".format(website))
            return None

        return self.passwords[website]


# Example usage
def main():
    pwd_manager = EncryptedPasswordManager()
    
    # Check if vault exists
    if not os.path.exists(pwd_manager.file_path):
        # Create new vault
        if not pwd_manager.create_vault():
            return
    else:
        # Load existing vault
        if not pwd_manager.load_vault():
            return
    
    # Now that the vault is loaded, perform operations
    print("\nPassword Manager Options:")
    print("1. Add new login")
    print("2. Update existing login")
    print("3. Get password")
    print("4. List all websites")
    print("5. Exit")
    
    while True:
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == '1':
            website = input("Enter website/app name: ")
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            if pwd_manager.create_login(website, username, password):
                print("Login added successfully!")
        
        elif choice == '2':
            website = input("Enter website/app name: ")
            update_type = input("What do you want to update? (user/pwd/both): ").lower()
            updates = {}
            
            if update_type in ['user', 'both']:
                updates['user'] = input("Enter new username: ")
            if update_type in ['pwd', 'both']:
                updates['pwd'] = getpass.getpass("Enter new password: ")
                
            if pwd_manager.update_login(website, updates):
                print("Login updated successfully!")
        
        elif choice == '3':
            website = input("Enter website/app name: ")
            username = pwd_manager.get_current_user(website)
            password = pwd_manager.get_current_pwd(website)
            
            if username and password:
                print("Username: {}".format(username))
                print("Password: {}".format(password))
        
        elif choice == '4':
            websites = pwd_manager.list_websites()
            if websites:
                print("Stored websites:")
                for site in websites:
                    print("- {}".format(site))
            else:
                print("No websites stored yet.")
        
        elif choice == '5':
            print("Exiting password manager.")
            break
        
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
