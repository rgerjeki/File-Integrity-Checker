File Integrity Checker
======================

Description
-----------

This Python program provides a simple utility to compute the SHA-256 hash of a file and check the file's integrity by comparing its current hash with a saved original hash.

Features
--------

- Computes and saves the SHA-256 hash of every file in the `Desktop`, `Documents`, and `Downloads` directories.
- Encrypted hash database using a user-provided password.
- Periodic integrity checks against the saved hashes.
- Visual progress bars using `tqdm`.
- Tabular summaries using `prettytable`.

How to Use
----------

### Initial Setup:

Run `run_first.py` script. This will compute the hashes of your files in the aforementioned directories and encrypt the resulting hash database using a password that you provide:

```bash
$ python3 run_first.py
```

### Periodic Integrity Check:

Execute the `file_integrity_check.py` script. This will ask for the encryption password, decrypt the saved hash database, check for new files to hash, and perform integrity checks against the saved hashes:

```bash
$ python3 file_integrity_check.py
```

Installation and Running
------------------------

1.  Ensure you have Python installed on your machine.
2.  Clone the repository:

```bash
$ git clone https://github.com/rgerjeki/file-integrity-checker.git
```

1.  Navigate to the directory containing the scripts using a terminal or command prompt.
2.  Follow the usage instructions above to compute hashes or perform integrity checks.

Dependencies
------------

-   Python's built-in libraries: `os`, `json`, and `hashlib`.
-   External libraries: `tqdm`, `prettytable`, and `cryptography`.

Troubleshooting
---------------

-   Ensure that you have the necessary permissions to read the files in the specified directories.
-   If you encounter decryption errors, verify that you have provided the correct password.

License
-------

This project is licensed under the MIT License. Check the `LICENSE` file for more details.

Contributing
------------

If you'd like to contribute, please fork the repository and use a feature branch. Pull requests are warmly welcome.

Author
------

[rgerjeki](https://github.com/rgerjeki)

Feel free to reach out if you have any questions or feedback!
