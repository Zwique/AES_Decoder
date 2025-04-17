import argparse
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import sys
from typing import Tuple

class CFBDecoder:
    """
    Decrypts data encrypted with AES-256-CFB (OpenSSL compatible)
    CFB mode turns a block cipher into a stream cipher
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
    def decrypt(enc_data: bytes, password: str, segment_size: int=128) -> bytes:
        """
        Decrypt AES-256-CFB encrypted data with OpenSSL format
        segment_size: Number of bits to process at a time (typically 8 or 128)
        """
        if not enc_data.startswith(b"Salted__"):
            raise ValueError("Invalid format: missing OpenSSL salt header")
            
        salt = enc_data[8:16]
        ciphertext = enc_data[16:]

        key, iv = CFBDecoder.evp_bytes_to_key(password, salt)
        
        try:
            # CFB doesn't require padding as it's a stream cipher mode
            cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=segment_size)
            return cipher.decrypt(ciphertext)
            
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description="Decrypt AES-256-CFB (OpenSSL format) encrypted data",
        epilog="Note: Segment size defaults to 128 bits (change with --segment-size)"
    )
    parser.add_argument('--input', required=True, help="Input file path")
    parser.add_argument('--password', required=True, help="Decryption password")
    parser.add_argument('--output', help="Output file path (optional)")
    parser.add_argument('--segment-size', type=int, default=128, 
                      choices=[8, 16, 32, 64, 128],
                      help="CFB segment size in bits (default: 128)")
    
    args = parser.parse_args()

    try:
        with open(args.input, "rb") as f:
            data = f.read()
        
        plaintext = CFBDecoder.decrypt(data, args.password, args.segment_size)
        
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