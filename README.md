# Secure File Encryption Utility

A lightweight command-line utility for AES-256-CBC file encryption, decryption, and rekeying, with optional secure file deletion using `shred`.

## Features

- 🔒 **AES-256 Encryption** using CBC mode
- 🧹 **Secure file deletion** using `shred` (or `os.remove` fallback)
- 🔑 **Rekeying** capability to rotate encryption keys
- 🛡️ **Padding/unpadding** logic for block alignment
- 🗂️ Specify optional output directory for results

## Requirements

- Python 3.6+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/)

Install dependencies:

```bash
pip install pycryptodome
```
## Usage
```bash
python secure_file_encryption.py -m <mode> -f <file> -k <key> [options]
```
### Modes

| Mode    | Description                      |
| ------- | -------------------------------- |
| encrypt | Encrypt the given file           |
| decrypt | Decrypt an `.encrypted` file     |
| rekey   | Re-encrypt a file with a new key |
---
## Options

| Option             | Description                         |
| ------------------ | ----------------------------------- |
| `-f`, `--file`     | Path to the input file              |
| `-k`, `--key`      | Encryption key                      |
| `-nk`, `--new-key` | New key (required for `rekey` mode) |
| `-o`, `--output`   | Optional output directory           |
---
## Examples

### Encrypt a file
```bash
python secure_file_encryption.py -m encrypt -f secrets.txt -k mysecretkey
```
### Decrypt a file
```bash
python secure_file_encryption.py -m decrypt -f secrets.txt.encrypted -k mysecretkey
```
### Rekey an encrypted file
```bash
python secure_file_encryption.py -m rekey -f secrets.txt.encrypted -k oldkey -nk newkey
```
## Secure Deletion

The script attempts to use shred -u to securely erase original files after encryption. If shred is unavailable, it falls back to regular deletion (os.remove).

    ⚠️ Ensure shred is installed on your system (sudo apt install coreutils on Debian/Ubuntu).

## ⚠️ Disclaimer

This utility is intended for educational and small-scale personal use.
## MIT License



## Official Channels

- [YouTube @rootctf](https://www.youtube.com/@rootctf)
- [X @r0otk3r](https://x.com/r0otk3r)

