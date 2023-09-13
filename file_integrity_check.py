import os
import json
import hashlib
import base64
from tqdm import tqdm
from prettytable import PrettyTable
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Global constants
ENCRYPTED_FILE = "encrypted_hashes.enc"


def compute_file_hash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_all_files_in_dirs():
    base_path = os.path.expanduser("~")  # This gets the home directory
    directories = ["Desktop", "Documents", "Downloads"]
    for directory in directories:
        directory_path = os.path.join(base_path, directory)
        if os.path.exists(directory_path):
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                        yield filepath


def key_derivation(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def decrypt_data(data, password):
    salt = data[:16]
    encrypted_data = data[16:]
    key = key_derivation(password, salt)
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode()


def encrypt_data(data, password):
    salt = os.urandom(16)
    key = key_derivation(password, salt)
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return salt + encrypted_data


def check_integrity(hashes_dict):
    failed_files = []
    passed_count = 0

    # Add progress bar for integrity checking
    with tqdm(total=len(hashes_dict), desc="Checking Integrity", unit="file", dynamic_ncols=True) as pbar:
        for filepath, saved_hash in hashes_dict.items():
            if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                current_hash = compute_file_hash(filepath)
                if current_hash != saved_hash:
                    failed_files.append((filepath, saved_hash))
                else:
                    passed_count += 1
                pbar.update(1)

    # Display the summary table
    table = PrettyTable()
    table.field_names = ["Integrity Check", "Count"]
    table.add_row(["Passed", passed_count])
    table.add_row(["Failed", len(failed_files)])
    print(table)

    # If there are failed integrities, list them out
    if failed_files:
        failed_table = PrettyTable()
        failed_table.field_names = ["File Path", "Original Hash"]
        for filepath, hash_val in failed_files:
            failed_table.add_row([filepath, hash_val])
        print("\nList of Files with Failed Integrity Check:")
        print(failed_table)


def update_new_files(hashes_dict, password):
    new_files = set(get_all_files_in_dirs()).difference(set(hashes_dict.keys()))

    # Add progress bar for updating new files
    with tqdm(total=len(new_files), desc="Updating New Files", unit="file", dynamic_ncols=True) as pbar:
        for filepath in new_files:
            # Check if the file still exists and is readable before processing
            if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                try:
                    file_hash = compute_file_hash(filepath)
                    hashes_dict[filepath] = file_hash
                    print(f"New file detected: {filepath}. Hash added.")
                except Exception as e:
                    print(f"Error processing {filepath}. Reason: {e}")
            pbar.update(1)

    # Encrypt the updated dictionary
    hashes_str = json.dumps(hashes_dict)
    encrypted_hashes = encrypt_data(hashes_str, password)
    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(encrypted_hashes)


def main():
    password = input("Enter the password: ")
    print("Trying to read encrypted file...")
    try:
        # Read and decrypt the file to get the saved hashes
        with open(ENCRYPTED_FILE, "rb") as f:
            encrypted_hashes = f.read()
        decrypted_hashes_str = decrypt_data(encrypted_hashes, password)
        hashes_dict = json.loads(decrypted_hashes_str)

        # Check for new files and update the encrypted file if needed
        update_new_files(hashes_dict, password)

        # Close any lingering tqdm instances
        tqdm._instances.clear()

        # Check integrity of all files present in the encrypted file
        check_integrity(hashes_dict)

        # Close any lingering tqdm instances
        tqdm._instances.clear()

        print("All tasks completed.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()