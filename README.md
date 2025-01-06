# File Encryption Tool

This repository contains a simple Python-based file encryption and decryption tool to secure your files using AES (Advanced Encryption Standard). It supports both encrypting and decrypting files via a command-line interface.


## Features (What It Offers)

- *AES Encryption/Decryption*: Uses a secure, industry-standard algorithm.
- *Command-Line Interface*: Easily encrypt or decrypt files from the terminal.
- *Password Protection*: Set your own password for encryption and decryption.
- *Cross-Platform*: Works on Windows, maCOS, and Linux (requires Python 3.x).


## Getting Started


### Prerequisites

-**Python 3.6+** must be installed on your machine.
- (Optional) Create a virtual environment for a clean setup:

`{bash
python -m venv venv

source venv/bin/activate # On Linux/Mac
venv\\Scripts\\activate     # On Windows
`}

### Installation

1. **Clone the repository**:
  `{bash
git clone https://github.com/suhaibsdkhan/file-encryption-tool.git
``
2. **Navigate into the folder**:
```bash
cd file-encryption-tool
```
if you are not already in the project folder, this will create one.

3. **Install required dependencies**:
```{bash
pip install -r requirements.txt```


## Usage

Below are examples of how to encrypt or decrypt files using the command-line interface.

### Run the Tool

1. **Encrypt a file**:
```{bash
python file_encrypt.py --encrypt --file /path/to/plain_file.txt
```
You will be prompted to enter a **password**. This password will be needed to decrypt the file.

2. **Decrypt a file**:
```{bash
python file_encrypt.py --decrypt --file /path/to/encrypted_file.enc
```
Enter the **same password** used during encryption.  
When the password is incorrect, decryption will fail.


### Command-line Options

```{raw
usage: file_encrypt.py [-h] [--encrypt] [--decrypt] [--file FILE]

optional arguments:
  -h, --help       show this help message and exit
  --encrypt       Encrypt the specified file
  --decrypt        Decrypt the specified file
  --file FILE         Path to the file to encrypt or decrypt


```

### Examples

o **Encrypting a file
```{bash
python file_encrypt.py --encrypt --file secret_data.txt
# Creates an encrypted file named secret_data.tx.enc
```

** Decrypting a file ** 
 ```bash
python file_encrypt.py --decrypt --file secret_data.tx.enc
# Decrypted file named secret_data.tx will be generated
```


### Project Structure

```file`
file-encryption-tool
\|
||-- file_encrypt.py           # Main script for encryption/decryption
||- requirements.txt           # Python libraries needed||- LICENSE                             # License (if provided)||- README.md                              # Project documentation (this file)```


### How It Works

1. ***Password Input***
###    The script prompts the user for a password. Make sure to remember this password as it's required for decryption.

2. **Key Derivation**

###    A secure key is derived from the supplied password using a key derivation function like PBKDF2. This provides additional security against brute-force attacks.

3. **AES Encryption**
###    The tool uses AES encryption in CBC (Cipher Block Chaining) mode, requiring an initialization vector (IV) to ensure unique encryptions even when files are identical.

4. ***File Output**

###    - **Encryption**: Reads the source file in chunks, encrypts each chunk, and writes to a new file with the .enc extension.
###    - **Decryption**: Reads the .enc file, decrypts it, and outputs the original file without the .enc extension.

### Security Considerations

###  - **Password Strength**: Choose a strong, unique password to protect your files.
###  - **Sharing the Password**: If you share your encrypted file with others, ensure you share the password via a secure channel.
### - **File Overwriting**: Decryption may overwrite an existing file with the same name. Back up important files before testing.


### Contributing

1. Fork this repository.
2. Create a new branch (`git checkout -b feature/new-featuer`).
/3. Commit your changes (`git commit -m "Add new featuer"`).
4. Push to your fork (`git push origin feature/new-feature`).
/5. Create a new Pull Request.

We welcome any contributions, including bug reports, bu fixes, documentation, and feature improvements.


### License

This project is licensed under the [MIT License](LICENSE). Feel free to use, modify, and distribute this software according to its terms.


### Contact

- **Author*: [Suhaib K.](https://github.com/suhaibsdkthan)
- **Project Link**: [file-encryption-tool](https://github.com/suhaibsdkhan/file-encryption-tool)

If you have any issues or suggestions, please open an [issue](https://github.com/suhaibsdkhan/file-encryption-tool/issues) or submit a Pull Request.


**Happy Encrypting!**
