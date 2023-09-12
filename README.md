# File Integrity Checker

## Description
This Python program provides a simple utility to compute the SHA-256 hash of a file and check the file's integrity by comparing its current hash with a given original hash.

## Features
- Compute the SHA-256 hash of a file.
- Check if a file has been modified or corrupted by comparing it with an original hash.

## How to Use

1. **Computing File Hash**
    - Run the program.
    - Choose option `1` to compute the hash of a file.
    - Enter the file's path.
    - The program will display the SHA-256 hash of the file.

2. **Checking File Integrity**
    - Run the program.
    - Choose option `2` to check the integrity of a file.
    - Enter the file's path.
    - Enter the original hash value of the file.
    - The program will compare the current hash of the file with the given original hash and notify if the file is intact or has been modified.

## Installation and Running

1. Ensure you have Python installed on your machine.
2. Clone the repository or download the Python script.
3. Navigate to the directory containing the script using a terminal or command prompt.
4. Run the script:
```bash
$ python3 file_integrity_check.py
```

## Dependencies
- Python's built-in `hashlib` library.

## Troubleshooting
- If you encounter the message "Invalid Filename Path.", ensure that:
- The file exists at the specified path.
- You have the necessary permissions to read the file.

- If you see the message "Invalid choice!", ensure you enter either `1` or `2` at the prompt.

## License
This project is open-source and available to everyone. Feel free to use, modify, or distribute as you see fit.

## Contribution
For any suggestions or improvements, please raise an issue or make a pull request on the repository.

## Contributing

If you'd like to contribute, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## License

This project is free and open-source. You can use, modify, and distribute it under the terms of the MIT License. Check the `LICENSE` file for more details.

## Author

[rgerjeki](https://github.com/rgerjeki)

Feel free to reach out if you have any questions or feedback!
