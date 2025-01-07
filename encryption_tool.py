#!/usr/bin/env python3
"""
Fancy File Encryption Tool

Features:
- AES encryption (EAX or GCM) with Scrypt-based key derivation
- GUI mode for everyday users
- CLI mode for power users, including chunk-based encryption and progress bar
- Secure random salt and nonce generation
- Progress bar for large file handling (CLI only)

Requires:
- pycryptodome (for AES, scrypt)
- tqdm (for CLI progress bar)
- tkinter (standard library for GUI)
"""

import os
import argparse
import base64
import logging
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk

# External libraries
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ----------------------------
# Utility / Core Crypto
# ----------------------------

def generate_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a secure key using scrypt.
    32-byte key is sufficient for AES-256.
    """
    return scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)

def encrypt_data(key: bytes, plaintext: bytes, mode: str) -> tuple:
    """
    Encrypt data using AES in the specified mode (EAX or GCM).
    Returns salt, nonce, tag, ciphertext.
    """
    if mode.upper() == "GCM":
        cipher = AES.new(key, AES.MODE_GCM)
    else:
        # Default to EAX
        cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, tag, ciphertext

def decrypt_data(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes, mode: str) -> bytes:
    """
    Decrypt data using AES in the specified mode (EAX or GCM).
    Returns plaintext.
    """
    if mode.upper() == "GCM":
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    else:
        # Default to EAX
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# ----------------------------
# GUI-Specific Functions
# (Encrypt/Decrypt in one go)
# ----------------------------

def encrypt_file_gui(file_path: str, password: str, mode: str):
    """
    Encrypt file in one go (for GUI usage).
    Writes salt + nonce + tag + ciphertext to .enc file.
    """
    try:
        salt = get_random_bytes(16)
        key = generate_key(password.encode(), salt)

        # Read the entire file at once
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        nonce, tag, ciphertext = encrypt_data(key, plaintext, mode)
        output_file = file_path + ".enc"

        with open(output_file, 'wb') as f:
            # Save salt + nonce + tag + ciphertext
            f.write(salt + nonce + tag + ciphertext)

        messagebox.showinfo("Success", f"File encrypted and saved as {output_file}")
    except Exception as e:
        logging.exception("Encryption error")
        messagebox.showerror("Error", f"An error occurred: {e}")

def decrypt_file_gui(file_path: str, password: str, mode: str):
    """
    Decrypt file in one go (for GUI usage).
    Expects salt(16) + nonce(16) + tag(16) + ciphertext.
    Removes .enc extension from output file.
    """
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        key = generate_key(password.encode(), salt)
        plaintext = decrypt_data(key, nonce, tag, ciphertext, mode)

        # Remove .enc extension
        if file_path.endswith(".enc"):
            output_file = file_path[:-4]
        else:
            output_file = file_path + ".dec"

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("Success", f"File decrypted and saved as {output_file}")
    except Exception as e:
        logging.exception("Decryption error")
        messagebox.showerror("Error", f"An error occurred: {e}")

# ----------------------------
# CLI-Specific Functions
# (Chunk-based Encryption/Decryption)
# ----------------------------

def encrypt_file_cli(input_path: str, output_path: str, password: str, mode: str):
    """
    Encrypt a file in chunks for CLI usage to handle large files gracefully.
    """
    try:
        salt = get_random_bytes(16)
        key = generate_key(password.encode(), salt)

        # Initialize cipher
        if mode.upper() == "GCM":
            cipher = AES.new(key, AES.MODE_GCM)
        else:
            cipher = AES.new(key, AES.MODE_EAX)

        # Use a buffer for chunk-based encryption
        chunk_size = 64 * 1024  # 64KB

        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            # Write salt, to be read on decryption
            fout.write(salt)
            # Nonce will be needed for decryption
            fout.write(cipher.nonce)

            # Read file in chunks
            file_size = os.path.getsize(input_path)
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Encrypting") as pbar:
                while True:
                    chunk = fin.read(chunk_size)
                    if not chunk:
                        break
                    encrypted_chunk = cipher.encrypt(chunk)
                    fout.write(encrypted_chunk)
                    pbar.update(len(chunk))

            # Finalize and write the tag
            tag = cipher.digest()
            fout.write(tag)

        logging.info("Encryption completed: %s", output_path)
    except Exception as e:
        logging.exception("Encryption error (CLI)")
        raise

def decrypt_file_cli(input_path: str, output_path: str, password: str, mode: str):
    """
    Decrypt a file in chunks for CLI usage to handle large files gracefully.
    """
    try:
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            salt = fin.read(16)
            nonce = fin.read(16)
            key = generate_key(password.encode(), salt)

            if mode.upper() == "GCM":
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            else:
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

            file_size = os.path.getsize(input_path) - 16 - 16 - 16  # subtract salt, nonce, tag
            chunk_size = 64 * 1024  # 64KB

            # We read everything except the last 16 bytes (tag).
            to_read = file_size
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Decrypting") as pbar:
                while to_read > 0:
                    chunk = fin.read(min(chunk_size, to_read))
                    if not chunk:
                        break
                    plaintext_chunk = cipher.decrypt(chunk)
                    fout.write(plaintext_chunk)
                    pbar.update(len(chunk))
                    to_read -= len(chunk)

            tag = fin.read(16)  # read the last 16 bytes
            cipher.verify(tag)

        logging.info("Decryption completed: %s", output_path)
    except Exception as e:
        logging.exception("Decryption error (CLI)")
        raise

# ----------------------------
# Tkinter GUI
# ----------------------------

def browse_file():
    filename = filedialog.askopenfilename()
    file_path_var.set(filename)

def perform_action(action):
    file_path = file_path_var.get()
    password = password_var.get()
    selected_mode = mode_var.get().strip()
    if not file_path or not password:
        messagebox.showwarning("Input Error", "Please provide both file path and password.")
        return

    if action == 'encrypt':
        encrypt_file_gui(file_path, password, selected_mode)
    elif action == 'decrypt':
        # Try to guess if the file is .enc to properly remove the extension
        decrypt_file_gui(file_path, password, selected_mode)

def launch_gui():
    root = tk.Tk()
    root.title("Fancy File Encryption Tool")

    global file_path_var, password_var, mode_var
    file_path_var = tk.StringVar()
    password_var = tk.StringVar()
    mode_var = tk.StringVar(value="EAX")  # default to EAX

    # File path
    tk.Label(root, text="File Path:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
    tk.Entry(root, textvariable=file_path_var, width=50).grid(row=0, column=1, padx=10, pady=10)
    tk.Button(root, text="Browse", command=browse_file).grid(row=0, column=2, padx=10, pady=10)

    # Password
    tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
    tk.Entry(root, textvariable=password_var, show='*', width=50).grid(row=1, column=1, padx=10, pady=10)

    # Mode dropdown
    tk.Label(root, text="AES Mode:").grid(row=2, column=0, padx=10, pady=10, sticky='e')
    mode_dropdown = ttk.Combobox(root, textvariable=mode_var, values=["EAX", "GCM"], state='readonly')
    mode_dropdown.grid(row=2, column=1, padx=10, pady=10, sticky='w')

    # Buttons
    tk.Button(root, text="Encrypt", command=lambda: perform_action('encrypt')).grid(row=3, column=1, padx=10, pady=10, sticky='w')
    tk.Button(root, text="Decrypt", command=lambda: perform_action('decrypt')).grid(row=3, column=1, padx=10, pady=10, sticky='e')

    root.mainloop()

# ----------------------------
# CLI Parsing
# ----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Fancy File Encryption Tool: AES-based encryption (EAX/GCM), with GUI or CLI usage."
    )
    subparsers = parser.add_subparsers(dest="command")

    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file (CLI)")
    encrypt_parser.add_argument("-f", "--file", required=True, help="Path to the input file")
    encrypt_parser.add_argument("-o", "--output", required=False, help="Output file path (default: input_file.enc)")
    encrypt_parser.add_argument("-p", "--password", required=True, help="Password for encryption")
    encrypt_parser.add_argument("-m", "--mode", choices=["EAX", "GCM"], default="EAX", help="AES mode (default: EAX)")

    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file (CLI)")
    decrypt_parser.add_argument("-f", "--file", required=True, help="Path to the input encrypted file")
    decrypt_parser.add_argument("-o", "--output", required=False, help="Output file path (default: input_file.dec or original filename if .enc)")
    decrypt_parser.add_argument("-p", "--password", required=True, help="Password for decryption")
    decrypt_parser.add_argument("-m", "--mode", choices=["EAX", "GCM"], default="EAX", help="AES mode (default: EAX)")

    # GUI subcommand
    gui_parser = subparsers.add_parser("gui", help="Launch the Tkinter GUI")

    args = parser.parse_args()

    if args.command == "encrypt":
        # CLI encrypt
        in_file = args.file
        out_file = args.output or (in_file + ".enc")
        encrypt_file_cli(in_file, out_file, args.password, args.mode)
        print(f"Encrypted file saved to: {out_file}")
    elif args.command == "decrypt":
        # CLI decrypt
        in_file = args.file
        if args.output:
            out_file = args.output
        else:
            # If file ends with .enc, remove extension, otherwise append .dec
            if in_file.endswith(".enc"):
                out_file = in_file[:-4]
            else:
                out_file = in_file + ".dec"
        decrypt_file_cli(in_file, out_file, args.password, args.mode)
        print(f"Decrypted file saved to: {out_file}")
    elif args.command == "gui":
        # Launch GUI
        launch_gui()
    else:
        # If no subcommand is specified, show help
        parser.print_help()

if __name__ == "__main__":
    main()