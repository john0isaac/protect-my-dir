# Protect My Dir

A command-line tool designed to encrypt and decrypt files within a directory using a password. It provides a simple and secure way to protect sensitive files using AES encryption .

## Features

- **AES Encryption**: Uses AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode with PKCS7 padding for secure encryption.
- **Password-Based Key Derivation**: Utilizes PBKDF2 with SHA256 for deriving encryption keys from passwords, ensuring strong security.
- **Salt and IV Generation**: Automatically generates a unique salt and initialization vector (IV) for each file to enhance security.
- **File Encryption**: Encrypts individual files and removes the original unencrypted files.
- **File Decryption**: Decrypts previously encrypted files and restores them to their original state.
- **Directory Support**: Recursively encrypts or decrypts all files in a specified directory.
- **Error Handling**: Provides meaningful error messages for incorrect passwords or corrupted files.
- **Cross-Platform**: Works on any platform that supports Python.

## Installation

1. Clone the repository:

   ```bash
    git clone https://github.com/john0isaac/protect-my-dir.git
    cd protect-my-dir
    ```

2. Create a virtual environment and Install the required dependencies using [uv](https://docs.astral.sh/uv/):

    ```bash
    uv sync
    ```

## Usage

The tool provides a CLI interface for encrypting and decrypting directories. Below are the available commands and options:

- Encrypt a Directory:

    To encrypt all files in a directory:

    ```bash
    protect-my-dir --directory /path/to/directory --encrypt
    ```

    You will be prompted to enter a password. The tool will encrypt all files in the directory and remove the original files.

- Decrypt a Directory:

    To decrypt all files in a directory:

    ```bash
    protect-my-dir --directory /path/to/directory --decrypt
    ```

    You will be prompted to enter the password used for encryption. The tool will decrypt all files in the directory and restore them to their original state.

Command-line options:

- `--directory` or `-dir`: Specify the directory containing files to encrypt or decrypt.
- `--encrypt` or `-e`: Encrypt the files in the specified directory.
- `--decrypt` or `-d`: Decrypts all `.enc` files in the specified directory.

## How It Works

1. Encryption:

    - A unique salt and IV are generated for each file.
    - The password is used to derive a 256-bit encryption key using PBKDF2.
    - The file is padded, encrypted, and saved with a `.enc` extension.
    - The original file is securely deleted.

1. Decryption:

    - The salt and IV are extracted from the encrypted file.
    - The password is used to derive the decryption key.
    - The file is decrypted, unpadded, and restored to its original state.
    - The encrypted file is securely deleted.

## Security Considerations

- **Password Strength**: Use a strong, unique password to ensure the security of your files.
- **Backup**: Always keep a backup of your password. If you lose it, the files cannot be decrypted.
- **File Removal**: The tool deletes original files after encryption and encrypted files after decryption. Ensure you have backups if needed.
