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

# Read and decrypt
with open("encrypted.txt", "rb") as f:
    data = f.read()

password = input("Enter password: ")
plaintext = decrypt_openssl(data, password)
print("Decrypted message:")
print(plaintext.decode(errors="replace"))
