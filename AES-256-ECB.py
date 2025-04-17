import argparse
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import sys
from typing import Tuple

class ECBDecoder:
    """
    Decrypts data encrypted with AES-256-ECB (OpenSSL compatible)
    Note: ECB mode is generally insecure for most use cases
    """
    
    @staticmethod
    def evp_bytes_to_key(password: str, salt: bytes, key_len: int=32) -> bytes:
        """
        OpenSSL key derivation function (ECB doesn't use IV)
        """
        d = d_i = b''
        while len(d) < key_len:
            d_i = MD5.new(d_i + password.encode() + salt).digest()
            d += d_i
        return d[:key_len]

    @staticmethod
    def decrypt(enc_data: bytes, password: str) -> bytes:
        """
        Decrypt AES-256-ECB encrypted data with OpenSSL format
        """
        if not enc_data.startswith(b"Salted__"):
            raise ValueError("Invalid format: missing OpenSSL salt header")
            
        salt = enc_data[8:16]
        ciphertext = enc_data[16:]

        key = ECBDecoder.evp_bytes_to_key(password, salt)
        
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            pt = cipher.decrypt(ciphertext)
            
            # PKCS7 unpad
            pad_len = pt[-1]
            if pad_len <= AES.block_size and all(p == pad_len for p in pt[-pad_len:]):
                pt = pt[:-pad_len]
            return pt
            
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt AES-256-ECB (OpenSSL format) encrypted data",
        epilog="Warning: ECB mode is not secure for most real-world applications"
    )
    parser.add_argument('--input', required=True, help="Input file path")
    parser.add_argument('--password', required=True, help="Decryption password")
    parser.add_argument('--output', help="Output file path (optional)")
    
    args = parser.parse_args()

    try:
        with open(args.input, "rb") as f:
            data = f.read()
        
        plaintext = ECBDecoder.decrypt(data, args.password)
        
        if args.output:
            with open(args.output, "wb") as f:
                f.write(plaintext)
            print(f"Successfully decrypted to {args.output}")
        else:
            print("Decrypted data:")
            print(plaintext.decode(errors="replace"))
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()