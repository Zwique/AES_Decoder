from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util.Padding import pad
from Crypto.Util import Counter  # Add this import for the counter functionality
import os
import sys
import argparse
from typing import Tuple

class OpenSSLEncryptor:
    """OpenSSL-compatible encryption with multiple modes"""
    
    MODES = {
        'ecb': AES.MODE_ECB,
        'cbc': AES.MODE_CBC,
        'cfb': AES.MODE_CFB,
        'ofb': AES.MODE_OFB,
        'ctr': AES.MODE_CTR
    }

    @staticmethod
    def evp_bytes_to_key(password: str, salt: bytes, key_len: int=32, iv_len: int=16) -> Tuple[bytes, bytes]:
        """OpenSSL key derivation function"""
        d = d_i = b''
        while len(d) < key_len + iv_len:
            d_i = MD5.new(d_i + password.encode() + salt).digest()
            d += d_i
        return d[:key_len], d[key_len:key_len+iv_len]

    @staticmethod
    def encrypt(data: bytes, password: str, mode: str, segment_size: int=128) -> bytes:
        """
        Encrypt data in OpenSSL format
        Returns: b'Salted__' + salt + ciphertext
        """
        if mode not in OpenSSLEncryptor.MODES:
            raise ValueError(f"Unsupported mode: {mode}")

        salt = os.urandom(8)  # 8 bytes of random salt
        key, iv = OpenSSLEncryptor.evp_bytes_to_key(password, salt)

        # Prepare the cipher parameters
        cipher_params = {'key': key}
        if mode != 'ecb':
            cipher_params['iv'] = iv
        if mode == 'cfb':
            cipher_params['segment_size'] = segment_size
        if mode == 'ctr':
            # CTR mode requires a counter, so we use a nonce + counter combination
            cipher_params['nonce'] = iv[:8]  # First 8 bytes as the nonce
            cipher_params['counter'] = Counter.new(64, prefix=iv[8:], initial_value=0)  # Use the rest as the counter

        cipher = AES.new(**cipher_params, mode=OpenSSLEncryptor.MODES[mode])

        # Apply padding for block modes (like CBC and ECB)
        if mode in ['ecb', 'cbc']:
            data = pad(data, AES.block_size)

        ciphertext = cipher.encrypt(data)
        return b"Salted__" + salt + ciphertext


def main():
    parser = argparse.ArgumentParser(description="Encrypt data with AES (OpenSSL compatible)", epilog="Supported modes: ecb, cbc, cfb, ofb, ctr")
    parser.add_argument('--input', required=True, help="Input file path")
    parser.add_argument('--password', required=True, help="Encryption password")
    parser.add_argument('--output', required=True, help="Output file path")
    parser.add_argument('--mode', required=True, choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'], help="Encryption mode")
    
    args = parser.parse_args()

    try:
        with open(args.input, "rb") as f:
            data = f.read()
        
        encrypted_data = OpenSSLEncryptor.encrypt(data, args.password, args.mode)

        with open(args.output, "wb") as f:
            f.write(encrypted_data)
        
        print(f"Encryption complete. Output saved to {args.output}")
    
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
