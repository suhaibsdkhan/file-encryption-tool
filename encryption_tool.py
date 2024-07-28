from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
import os
import argparse
import tkinter as tk
from tkinter import filedialog, messagebox

# Generate a key from a password
def generate_key(password: bytes, salt: bytes) -> bytes:
    return scrypt(password, salt, 32, N=2**14, r=8, p=1)

# Encrypt a file
def encrypt_file(file_path: str, password: str):
    try:
        salt = get_random_bytes(16)
        key = generate_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_EAX)
        
        with open(file_path, 'rb') as file:
            plaintext = file.read()
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        with open(file_path + ".enc", 'wb') as file:
            file.write(salt + cipher.nonce + tag + ciphertext)
        
        messagebox.showinfo("Success", f"File encrypted and saved as {file_path}.enc")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Decrypt a file
def decrypt_file(file_path: str, password: str):
    try:
        with open(file_path, 'rb') as file:
            salt = file.read(16)
            nonce = file.read(16)
            tag = file.read(16)
            ciphertext = file.read()
        
        key = generate_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        with open(file_path[:-4], 'wb') as file:
            file.write(plaintext)
        
        messagebox.showinfo("Success", f"File decrypted and saved as {file_path[:-4]}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# GUI for file encryption/decryption
def browse_file():
    filename = filedialog.askopenfilename()
    file_path_var.set(filename)

def perform_action(action):
    file_path = file_path_var.get()
    password = password_var.get()
    if not file_path or not password:
        messagebox.showwarning("Input Error", "Please provide both file path and password.")
        return
    if action == 'encrypt':
        encrypt_file(file_path, password)
    elif action == 'decrypt':
        decrypt_file(file_path, password)

# Setup the GUI
root = tk.Tk()
root.title("File Encryption Tool")

file_path_var = tk.StringVar()
password_var = tk.StringVar()

tk.Label(root, text="File Path:").grid(row=0, column=0, padx=10, pady=10)
tk.Entry(root, textvariable=file_path_var, width=50).grid(row=0, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=browse_file).grid(row=0, column=2, padx=10, pady=10)

tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)
tk.Entry(root, textvariable=password_var, show='*', width=50).grid(row=1, column=1, padx=10, pady=10)

tk.Button(root, text="Encrypt", command=lambda: perform_action('encrypt')).grid(row=2, column=1, padx=10, pady=10, sticky='w')
tk.Button(root, text="Decrypt", command=lambda: perform_action('decrypt')).grid(row=2, column=1, padx=10, pady=10, sticky='e')

root.mainloop()