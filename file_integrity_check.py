import hashlib

def compute_file_hash(filename):
    """Compute and return the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    
    with open(filename, "rb") as f:
        # Read and update hash in chunks to save memoryfi
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

def main():
    print("File Integrity Checker")
    choice = input("Choose an action:\n1. Compute file hash\n2. Check file integrity\n> ")

    if choice == "1":
        try:
            filename = input("Enter the filename path to compute its hash: ")
            computed_hash = compute_file_hash(filename)
            print(f"Computed Hash: {computed_hash}")
        except:
            print("Invalid Filename Path.")

    elif choice == "2":
        try:
            filename = input("Enter the filename to check its integrity: ")
            original_hash = input("Enter the original hash value: ")
            current_hash = compute_file_hash(filename)
            
            if current_hash == original_hash:
                print("File is intact. No changes detected.")
            else:
                print("File has been modified or corrupted!")
        except:
            print("Invalid Filename Path.")

    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()

