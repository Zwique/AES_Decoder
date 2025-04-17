# AES_Decoder 🔐🔑
A collection of Python scripts for decoding and encrypting data using different AES (Advanced Encryption Standard) modes.

---

## Overview 🌐
This repository contains multiple Python scripts for working with AES encryption and decryption in different modes, including:

- **AES-256-CBC.py** (Cipher Block Chaining)
- **AES-256-CFB.py** (Cipher Feedback)
- **AES-256-ECB.py** (Electronic Codebook)
- **AES-256-OFB.py** (Output Feedback)

Each script is designed to handle AES encryption with a 256-bit key and provides functionality to decrypt data that has been encrypted using these modes. The scripts support OpenSSL-compatible encryption formats and can be used to handle encrypted data efficiently.

---

## Features 🛠️

- **AES-256-CBC**: Provides secure block encryption using Cipher Block Chaining. It requires padding for the input data.
- **AES-256-CFB**: Uses Cipher Feedback mode to provide stream-like encryption. It’s useful for encrypting data where you need to process it bit by bit.
- **AES-256-ECB**: Electronic Codebook mode that directly encrypts the data block-by-block. While simple, it is less secure compared to other modes due to patterns in the ciphertext.
- **AES-256-OFB**: Output Feedback mode, which also turns a block cipher into a stream cipher, similar to CFB but with different feedback mechanics.

---

## Installation 🖥️

To use these scripts, ensure you have Python installed on your system. You will also need the following Python libraries:

- **pycryptodome**: Used for AES encryption and decryption.

To install the required dependencies, run the following command:

```bash
pip install pycryptodome
```

Usage 🚀
Decrypt Data 🔓
Each script can be used to decrypt data from a file using the specified AES mode. You can run the scripts from the command line by specifying the input file and the decryption password.

```bash
python3 AES-256-<mode>.py --input <input_file> --password <your_password>
```
Replace <mode> with the mode of encryption, <input_file> with the path to the file you wish to decrypt, and <your_password> with the password used to encrypt the data.

Encrypt Data 🔒
The encryption scripts can also be used by specifying the encryption mode (e.g., --mode ctr for AES-CTR). You can use the following command to encrypt data:

```bash
python3 encryption.py --input <input_file> --password <your_password> --mode <encryption_mode> --output <output_file>
Command-Line Arguments 📝
--input (required): Path to the input file for encryption or decryption.

--password (required): Password for AES key derivation.

--mode (optional): Specifies the encryption mode (e.g., cbc, cfb, ecb, ofb).

--output (optional): Path to the output file where the encrypted/decrypted data will be saved.
```

Example 🎯
```bash
python3 encryption.py --input secret.txt  --password "supersecretpasswd" --mode ctr -- output data.enc
```
Contributing 🤝
Feel free to fork this repository and submit pull requests for improvements, bug fixes, or additional AES modes. All contributions are welcome! 😊

