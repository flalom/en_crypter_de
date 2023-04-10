# -*- coding: utf-8 -*-
"""
Spyder Editor
This script will generate a small tkinter windows where a file can be encrypted and decrypted with password 
and password protected

Author = FLavio Lombardo
"""

import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

backend = default_backend()

def encrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()

    ct = encryptor.update(data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(base64.b64encode(salt + iv + ct))

def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        data = base64.b64decode(f.read())

    salt = data[:16]
    iv = data[16:32]
    ct = data[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    data = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(data) + unpadder.finalize()

    with open(output_file, 'wb') as f:
        f.write(data)

def browse_input_file():
    input_file = filedialog.askopenfilename()
    input_file_var.set(input_file)

def browse_output_file():
    output_file = filedialog.asksaveasfilename()
    output_file_var.set(output_file)

def encrypt_button_clicked():
    input_file = input_file_var.get()
    output_file = output_file_var.get()
    password = password_var.get()

    if input_file and output_file and password:
        encrypt_file(input_file, output_file, password)

def decrypt_button_clicked():
    input_file = input_file_var.get()
    output_file = output_file_var.get()
    password = password_var.get()

    if input_file and output_file and password:
        decrypt_file(input_file, output_file, password)

root = tk.Tk()
root.title('File Encryptor and Decryptor')

input_file_var = tk.StringVar()
output_file_var = tk.StringVar()
password_var = tk.StringVar()

input_file_label = tk.Label(root, text='Input File:')
input_file_label.grid(row=0, column=0)
input_file_entry = tk.Entry(root, textvariable=input_file_var)
input_file_entry.grid(row=0, column=1)
input_file_button = tk.Button(root, text='Browse', command=browse_input_file)
input_file_button.grid(row=0, column=2)

output_file_label = tk.Label(root, text='Output File:')
output_file_label.grid(row=1, column=0)
output_file_entry = tk.Entry(root, textvariable=output_file_var)
output_file_entry.grid(row=1, column=1)
output_file_button = tk.Button(root, text='Browse', command=browse_output_file)
output_file_button.grid(row=1, column=2)

password_label = tk.Label(root, text='Password:')
password_label.grid(row=2, column=0)
password_entry = tk.Entry(root, textvariable=password_var, show='*')
password_entry.grid(row=2, column=1)

encrypt_button = tk.Button(root, text='Encrypt', command=encrypt_button_clicked)
encrypt_button.grid(row=3, column=0, columnspan=3)

decrypt_button = tk.Button(root, text='Decrypt', command=decrypt_button_clicked)
decrypt_button.grid(row=4, column=0, columnspan=3)

root.mainloop()
