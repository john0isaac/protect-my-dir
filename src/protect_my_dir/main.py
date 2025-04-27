"""
Main module for the protect_my_dir CLI tool.
This module provides functionality to encrypt and decrypt files in a directory
using a password.
It uses the AES encryption algorithm with CBC mode and PKCS7 padding.
It also uses PBKDF2 for key derivation with SHA256.
"""

import secrets
from pathlib import Path

import click
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from the password and salt."""
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())


def encrypt_file(file_path: Path, password: str) -> None:
    """Encrypt a single file with the given password."""
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)

    with file_path.open("rb") as f:
        plaintext = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = file_path.with_suffix(file_path.suffix + ".enc")
    with encrypted_file_path.open("wb") as f:
        f.write(salt + iv + ciphertext)

    file_path.unlink()  # Remove the original file


def encrypt_directory(directory: Path, password: str) -> None:
    """Encrypt all files in a directory."""
    for file_path in directory.rglob("*"):  # Recursively find all files
        if file_path.is_file():
            encrypt_file(file_path, password)


def decrypt_file(file_path: Path, password: str) -> None:
    """Decrypt a single file with the given password."""
    try:
        with file_path.open("rb") as f:
            data = f.read()

        salt = data[:16]  # Extract the salt (first 16 bytes)
        iv = data[16:32]  # Extract the IV (next 16 bytes)
        ciphertext = data[32:]  # The rest is the ciphertext

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        original_file_path = file_path.with_suffix("")  # Remove the `.enc` suffix
        with original_file_path.open("wb") as f:
            f.write(plaintext)

        file_path.unlink()  # Remove the encrypted file
    except Exception:
        click.echo(f"Failed to decrypt {file_path.name}: Incorrect password or corrupted file.")


def decrypt_directory(directory: Path, password: str) -> None:
    """Decrypt all files in a directory."""
    for file_path in directory.rglob("*.enc"):  # Find all encrypted files
        if file_path.is_file():
            decrypt_file(file_path, password)


@click.command()
@click.option(
    "-dir",
    "--directory",
    type=click.Path(path_type=Path, exists=True, file_okay=False, dir_okay=True, readable=True),
    help="Path to the directory to protect",
    required=True,
)
@click.option(
    "-d",
    "--decrypt",
    is_flag=True,
    help="Decrypt the directory instead of encrypting it",
)
@click.option(
    "-e",
    "--encrypt",
    is_flag=True,
    help="Encrypt the directory instead of decrypting it",
)
def protect(directory: Path, decrypt: bool, encrypt: bool) -> None:
    """Protect a directory by encrypting its contents."""
    password = click.prompt("Enter a password to protect the directory", hide_input=True)
    if not password:
        click.echo("Password cannot be empty.")
        return

    if not directory.is_dir():
        click.echo(f"{directory} is not a valid directory.")
        return

    if decrypt and encrypt:
        click.echo("Please specify either --decrypt or --encrypt, not both.")
        return

    if decrypt:
        decrypt_directory(directory, password)
        click.echo(f"Finished decrypting directory {directory}.")
    elif encrypt:
        encrypt_directory(directory, password)
        click.echo(f"Finished encrypting directory {directory}.")
    else:
        click.echo("No action specified. Please use --encrypt or --decrypt.")
        return


def main() -> None:
    """Main function to run the CLI."""
    protect()
