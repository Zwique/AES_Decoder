import argparse
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import sys
from typing import Tuple

class OFBDecoder:
    """
    Decrypts data encrypted with AES-256-OFB (OpenSSL compatible)
    OFB mode turns a block cipher into a stream cipher.
    """
    
    @staticmethod
    def evp_bytes_to_key(password: str, salt: bytes, key_len: int=32, iv_len: int=16) -> Tuple[bytes, bytes]:
        """
        OpenSSL key derivation function
        """
        d = d_i = b''
        while len(d) < key_len + iv_len:
            d_i = MD5.new(d_i + password.encode() + salt).digest()
            d += d_i
        return d[:key_len], d[key_len:key_len+iv_len]

    @staticmethod
    def decrypt(enc_data: bytes, password: str) -> bytes:
        """
        Decrypt AES-256-OFB encrypted data with OpenSSL format
        """
        if not enc_data.startswith(b"Salted__"):
            raise ValueError("Invalid format: missing OpenSSL salt header")
            
        salt = enc_data[8:16]
        ciphertext = enc_data[16:]

        key, iv = OFBDecoder.evp_bytes_to_key(password, salt)
        
        try:
            # OFB mode does not require padding as it's a stream cipher mode
            cipher = AES.new(key, AES.MODE_OFB, iv=iv)
            return cipher.decrypt(ciphertext)
            
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt AES-256-OFB (OpenSSL format) encrypted data",
        epilog="Note: This script assumes the input data is in OpenSSL encrypted format."
    )
    parser.add_argument('--input', required=True, help="Input file path")
    parser.add_argument('--password', required=True, help="Decryption password")
    parser.add_argument('--output', help="Output file path (optional)")
    
    args = parser.parse_args()

    try:
        with open(args.input, "rb") as f:
            data = f.read()
        
        plaintext = OFBDecoder.decrypt(data, args.password)
        
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
