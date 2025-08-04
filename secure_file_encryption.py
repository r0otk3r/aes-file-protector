#!/usr/bin/env python3
#By r0otk3r

import os
import sys
import argparse
import hashlib
import subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class FileCrypto:
    def __init__(self, filepath, key, output_dir=None):
        self.filepath = filepath
        self.output_dir = output_dir or os.path.dirname(filepath)
        self.key = hashlib.sha256(key.encode()).digest()
        self.block_size = AES.block_size

    def pad(self, data):
        pad_len = self.block_size - len(data) % self.block_size
        return data + bytes([pad_len]) * pad_len

    def unpad(self, data):
        return data[:-data[-1]]

    def secure_delete(self, target):
        try:
            subprocess.run(["shred", "-u", target], check=True)
        except Exception:
            os.remove(target)

    def encrypt(self):
        iv = get_random_bytes(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        with open(self.filepath, "rb") as f:
            plain = f.read()

        ciphered = cipher.encrypt(self.pad(plain))
        output_file = os.path.join(self.output_dir, os.path.basename(self.filepath) + ".encrypted")

        with open(output_file, "wb") as f:
            f.write(iv + ciphered)

        self.secure_delete(self.filepath)
        print(f"Encrypted: {output_file}")

    def decrypt(self):
        with open(self.filepath, "rb") as f:
            data = f.read()

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain = self.unpad(cipher.decrypt(ciphertext))

        out_name = os.path.basename(self.filepath).replace(".encrypted", ".decrypted")
        output_file = os.path.join(self.output_dir, out_name)

        with open(output_file, "wb") as f:
            f.write(plain)

        print(f"Decrypted: {output_file}")

    def rekey(self, new_key):
        temp_dec = os.path.join(self.output_dir, "temp_rekey")

        with open(self.filepath, "rb") as f:
            data = f.read()

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain = self.unpad(cipher.decrypt(ciphertext))

        with open(temp_dec, "wb") as f:
            f.write(plain)

        new_crypto = FileCrypto(temp_dec, new_key, self.output_dir)
        new_crypto.encrypt()

        os.remove(temp_dec)
        print("Rekey completed.")

def parse_args():
    parser = argparse.ArgumentParser(description="Simple File Encryptor/Decryptor")
    parser.add_argument("-m", "--mode", choices=["encrypt", "decrypt", "rekey"], required=True, help="Mode")
    parser.add_argument("-f", "--file", required=True, help="Target file")
    parser.add_argument("-k", "--key", required=True, help="Encryption key")
    parser.add_argument("-nk", "--new-key", help="New key (for rekey)")
    parser.add_argument("-o", "--output", help="Output directory")
    return parser.parse_args()

def main():
    args = parse_args()

    if not os.path.isfile(args.file):
        print(f"File not found: {args.file}")
        sys.exit(1)

    crypto = FileCrypto(args.file, args.key, args.output)

    try:
        if args.mode == "encrypt":
            crypto.encrypt()
        elif args.mode == "decrypt":
            crypto.decrypt()
        elif args.mode == "rekey":
            if not args.new_key:
                print("Rekey mode requires --new-key")
                sys.exit(1)
            crypto.rekey(args.new_key)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
