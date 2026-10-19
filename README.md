# file-encryption-tool

Encrypts and decrypts files with a password, from a Tkinter window or the command line. First version written in summer 2024.

- AES-256 in GCM or EAX mode, so a wrong password or a tampered file fails the tag check instead of producing garbage
- Key derived from the password with scrypt (N=2^14, r=8, p=1) and a fresh 16-byte salt per file
- Streams the file in 64 KB chunks, so large files don't have to fit in memory

## Usage

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pycryptodome tqdm

python encryption_tool.py encrypt -f report.pdf -m GCM      # asks for the password, writes report.pdf.enc
python encryption_tool.py decrypt -f report.pdf.enc -m GCM  # writes report.pdf
python encryption_tool.py gui
```

You can pass `-p` instead of typing the password, but then it ends up in your shell history.

## File format

```
salt (16) | nonce (16) | ciphertext | tag (16)
```

The GUI and CLI write the same format. Earlier versions didn't (the GUI put the tag before the ciphertext), so a file made in one couldn't be opened in the other.

## Limitations

- The mode isn't stored in the file, so you have to decrypt with the same `-m` you encrypted with.
- Decryption writes chunks before the tag can be checked at the end. If the check fails, the partial output is deleted, but for a moment unverified plaintext is on disk.
