import argparse
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import base64

def evp_bytes_to_key(password, salt, key_len, iv_len):
    d = d_i = b''
    while len(d) < key_len + iv_len:
        d_i = MD5.new(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len+iv_len]

def decrypt_openssl(enc_data, password):
    assert enc_data.startswith(b"Salted__")
    salt = enc_data[8:16]
    ciphertext = enc_data[16:]

    key, iv = evp_bytes_to_key(password.encode(), salt, 32, 16)  # AES-256-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ciphertext)

    # Try to unpad (PKCS7)
    pad_len = pt[-1]
    if all(p == pad_len for p in pt[-pad_len:]):
        pt = pt[:-pad_len]
    return pt

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Decrypt AES-256-CBC encrypted data.")
    parser.add_argument('--input', type=str, required=True, help="Path to the encrypted file.")
    parser.add_argument('--password', type=str, required=True, help="Password for decryption.")
    args = parser.parse_args()

    # Read and decrypt the file
    with open(args.input, "rb") as f:
        data = f.read()

    plaintext = decrypt_openssl(data, args.password)
    print("Decrypted message:")
    print(plaintext.decode(errors="replace"))

if __name__ == "__main__":
    main()
