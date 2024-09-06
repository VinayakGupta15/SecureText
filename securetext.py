import os
import base64
from tkinter import Tk, Label, Text, Button, END, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants
SALT = b'secure_salt'
AES_BLOCK_SIZE = 16

class SecureTextApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureText: Text Encryption")

        # Encryption/Decryption keys
        self.aes_key = None
        self.rsa_private_key = None
        self.rsa_public_key = None

        # UI Setup
        self.setup_ui()

    def setup_ui(self):
        Label(self.root, text="Enter your message:").grid(row=0, column=0, padx=10, pady=10)

        self.input_text = Text(self.root, height=10, width=50)
        self.input_text.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

        Button(self.root, text="Encrypt with AES", command=self.encrypt_aes).grid(row=2, column=0, padx=10, pady=5)
        Button(self.root, text="Decrypt with AES", command=self.decrypt_aes).grid(row=2, column=1, padx=10, pady=5)

        Button(self.root, text="Encrypt with RSA", command=self.encrypt_rsa).grid(row=3, column=0, padx=10, pady=5)
        Button(self.root, text="Decrypt with RSA", command=self.decrypt_rsa).grid(row=3, column=1, padx=10, pady=5)

        Button(self.root, text="Generate RSA Keys", command=self.generate_rsa_keys).grid(row=4, column=0, columnspan=2, pady=10)

    def encrypt_aes(self):
        plaintext = self.input_text.get("1.0", END).strip()
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter a message to encrypt.")
            return

        self.aes_key = self.generate_aes_key()

        iv = os.urandom(AES_BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Padding
        pad_length = AES_BLOCK_SIZE - (len(plaintext) % AES_BLOCK_SIZE)
        plaintext += chr(pad_length) * pad_length

        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        encoded_ciphertext = base64.b64encode(iv + ciphertext).decode()

        self.input_text.delete("1.0", END)
        self.input_text.insert("1.0", encoded_ciphertext)

    def decrypt_aes(self):
        encoded_ciphertext = self.input_text.get("1.0", END).strip()
        if not encoded_ciphertext:
            messagebox.showwarning("Warning", "Please enter a message to decrypt.")
            return

        try:
            ciphertext = base64.b64decode(encoded_ciphertext.encode())
            iv = ciphertext[:AES_BLOCK_SIZE]
            actual_ciphertext = ciphertext[AES_BLOCK_SIZE:]

            cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext_padded = decryptor.update(actual_ciphertext) + decryptor.finalize()

            # Remove padding
            pad_length = plaintext_padded[-1]
            plaintext = plaintext_padded[:-pad_length].decode()

            self.input_text.delete("1.0", END)
            self.input_text.insert("1.0", plaintext)

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def encrypt_rsa(self):
        plaintext = self.input_text.get("1.0", END).strip()
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter a message to encrypt.")
            return

        if not self.rsa_public_key:
            messagebox.showwarning("Warning", "RSA keys are not generated. Please generate the RSA keys first.")
            return

        # Encrypt message
        try:
            ciphertext = self.rsa_public_key.encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            encoded_ciphertext = base64.b64encode(ciphertext).decode()

            self.input_text.delete("1.0", END)
            self.input_text.insert("1.0", encoded_ciphertext)

        except Exception as e:
            messagebox.showerror("Error", f"RSA encryption failed: {str(e)}")

    def decrypt_rsa(self):
        encoded_ciphertext = self.input_text.get("1.0", END).strip()
        if not encoded_ciphertext:
            messagebox.showwarning("Warning", "Please enter a message to decrypt.")
            return

        if not self.rsa_private_key:
            messagebox.showwarning("Warning", "RSA keys are not generated. Please generate the RSA keys first.")
            return

        # Decrypt message
        try:
            ciphertext = base64.b64decode(encoded_ciphertext.encode())

            plaintext = self.rsa_private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            self.input_text.delete("1.0", END)
            self.input_text.insert("1.0", plaintext.decode())

        except Exception as e:
            messagebox.showerror("Error", f"RSA decryption failed: {str(e)}")

    def generate_aes_key(self):
        password = "secure_password".encode()  # In practice, use a secure method to obtain the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)
        return key

    def generate_rsa_keys(self):
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        messagebox.showinfo("Info", "RSA keys generated successfully.")

        # Save keys to files (optional)
        with open("private_key.pem", "wb") as f:
            f.write(self.rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("public_key.pem", "wb") as f:
            f.write(self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))


if __name__ == "__main__":
    root = Tk()
    app = SecureTextApp(root)
    root.mainloop()
