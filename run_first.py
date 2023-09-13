import os
import json
import hashlib
import base64
from tqdm import tqdm
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Global constants
ENCRYPTED_FILE = "encrypted_hashes.enc"


def compute_file_hash(filename):
    sha256_hash = hashlib.sha256()
    try:
        with open(filename, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None


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


def encrypt_data(data, password):
    salt = os.urandom(16)
    key = key_derivation(password, salt)
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return salt + encrypted_data


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


def main():
    password = input("Enter a password to encrypt the hash database: ")

    print("Gathering file paths from Desktop, Documents, and Downloads...")

    filepaths = list(get_all_files_in_dirs())

    hashes_dict = {}

    print("Calculating hashes for all readable files...")
    for filepath in tqdm(filepaths, unit="file", dynamic_ncols=True):
        file_hash = compute_file_hash(filepath)
        if file_hash is not None:
            hashes_dict[filepath] = file_hash

    # Close the hashing progress bar explicitly
    tqdm._instances.clear()

    # Now let's create a progress bar for the next steps
    steps_description = ["Serializing data", "Encrypting data", "Writing to file"]
    progress_bar = tqdm(total=len(steps_description), desc="Saving data", dynamic_ncols=True)

    # Serialization
    time.sleep(0.5)  # This is just so that you can observe the progress bar
    hashes_str = json.dumps(hashes_dict)
    progress_bar.set_description(steps_description.pop(0))
    progress_bar.update(1)

    # Encryption
    time.sleep(0.5)  # As before, it's for observation purposes
    encrypted_hashes = encrypt_data(hashes_str, password)
    progress_bar.set_description(steps_description.pop(0))
    progress_bar.update(1)

    # Write to file
    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(encrypted_hashes)
    progress_bar.set_description(steps_description.pop(0))
    progress_bar.update(1)
    progress_bar.close()

    print("All file hashes from Desktop, Documents, and Downloads saved and encrypted.")


if __name__ == "__main__":
    main()
