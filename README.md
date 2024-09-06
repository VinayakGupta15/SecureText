# SecureText: Enhancing Communication Privacy through Text Encryption

##  Overview

**SecureText** is a Python-based application designed to provide secure text encryption and decryption using industry-standard cryptographic algorithms. It features a simple graphical user interface (GUI) that enables users to easily encrypt and decrypt messages, ensuring that sensitive information remains confidential.

### Features

- **Encryption and Decryption**: Secure your text messages using AES and RSA encryption.
- **Hashing**: Use SHA-256 for generating secure message digests.
- **User-friendly GUI**: Easy-to-use interface built with Tkinter.
- **Key Management**: Generate and manage cryptographic keys effortlessly.

### Technology Stack

- **Programming Language**: Python
- **Cryptographic Libraries**: `cryptography` and `PyCryptodome`
- **GUI Framework**: Tkinter

## Prerequisites

Ensure you have Python 3.x installed on your system. You can download it from [python.org](https://www.python.org/).

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/SecureText.git
   cd SecureText
   ```

2. **Create a Virtual Environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. **Install Required Packages**

   ```bash
   pip install -r requirements.txt
   ```
---
## Methodology

1. **Algorithm Selection**: The application uses AES for symmetric encryption and RSA for asymmetric encryption. SHA-256 is used for hashing.
   
2. **Key Management**: AES keys are derived from a password using PBKDF2HMAC for security. RSA keys are generated dynamically and can be stored for reuse.

3. **GUI Design**: A Tkinter-based GUI provides an intuitive interface for encrypting and decrypting messages.

4. **Testing and Validation**: The application will be tested rigorously to ensure reliability and security.

---
## Usage

1. **Encrypting Text with AES**:
   - Enter the text in the provided text area.
   - Click on "Encrypt with AES" to encrypt the text
   - The encrypted text will be displayed in the text area.

2. **Decrypting Text with AES**:
   - Enter the AES-encrypted text in the text area.
   - Click on "Decrypt with AES" to decrypt the text.
   - The decrypted text will be displayed.

3. **Generating RSA Keys**:
   - Click on "Generate RSA Keys" to generate a new pair of RSA keys.
   - The keys are stored in the application for encryption and decryption.

4. **Encrypting Text with RSA**:
   - Enter the text in the text area.
   - Click on "Encrypt with RSA" after generating RSA keys.
   - The RSA-encrypted text will be displayed.

5. **Decrypting Text with RSA**:
   - Enter the RSA-encrypted text in the text area.
   - Click on "Decrypt with RSA" to decrypt the text.
   - The decrypted text will be displayed.



## Conclusion

**SecureText** aims to provide a robust solution for text encryption, ensuring secure communication in the digital world. By implementing AES and RSA encryption algorithms, SecureText empowers users to protect their textual data, fostering trust and confidence in digital interactions.