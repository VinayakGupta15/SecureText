import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import base64

# Function to generate RSA key pair
def generate_rsa_keys():
    global private_key, public_key
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    messagebox.showinfo("Success", "RSA Keys Generated Successfully!")

# Function to encrypt text using RSA
def encrypt_text():
    if not public_key:
        messagebox.showwarning("Error", "Please generate RSA keys first!")
        return
    
    text = text_entry.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Error", "Please enter text to encrypt!")
        return
    
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_text = cipher.encrypt(text.encode('utf-8'))
    text_entry.delete("1.0", tk.END)
    text_entry.insert("1.0", base64.b64encode(encrypted_text).decode('utf-8'))

# Function to decrypt text using RSA
def decrypt_text():
    if not private_key:
        messagebox.showwarning("Error", "Please generate RSA keys first!")
        return
    
    encrypted_text = text_entry.get("1.0", tk.END).strip()
    if not encrypted_text:
        messagebox.showwarning("Error", "Please enter encrypted text to decrypt!")
        return
    
    try:
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode('utf-8')
        text_entry.delete("1.0", tk.END)
        text_entry.insert("1.0", decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed! Check your input.")

# GUI Functions
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_label.config(text=f"Selected File: {file_path}")
        file_label.file_path = file_path

# Creating the GUI
root = tk.Tk()
root.title("File & Text Encryption & Decryption Tool")
root.geometry("500x400")

# RSA Key Generation Button
generate_key_button = tk.Button(root, text="Generate RSA Keys", command=generate_rsa_keys)
generate_key_button.pack(pady=5)

file_button = tk.Button(root, text="Select File", command=select_file)
file_button.pack(pady=10)

file_label = tk.Label(root, text="No file selected")
file_label.pack(pady=5)

text_entry = tk.Text(root, height=5, width=50)
text_entry.pack(pady=5)

encrypt_text_button = tk.Button(root, text="Encrypt Text", command=encrypt_text)
encrypt_text_button.pack(pady=5)

decrypt_text_button = tk.Button(root, text="Decrypt Text", command=decrypt_text)
decrypt_text_button.pack(pady=5)

exit_button = tk.Button(root, text="Exit", command=root.quit)
exit_button.pack(pady=10)

# Initialize key variables
private_key = None
public_key = None

root.mainloop()
