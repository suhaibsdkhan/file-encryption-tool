
# Fancy File Encryption Tool

A more advanced file encryption/decryption utility that supports **AES** (EAX or GCM) with **scrypt**-based key derivation. It provides both a **GUI** (built with Tkinter) and a **CLI** interface for convenience.

## Features

- **AES-256** encryption (via EAX or GCM mode).
- **Secure password-based key derivation** using **scrypt**.
- **Random salt and nonce** for every encryption operation.
- **GUI** for easy operation (encrypt/decrypt).
- **CLI** with chunk-based encryption/decryption and a **progress bar** (using `tqdm`) for large files.
- **Logging** of encryption/decryption steps and improved error handling.

## Requirements

- Python 3.6+
- [pycryptodome](https://pypi.org/project/pycryptodome/) for AES and scrypt
- [tqdm](https://pypi.org/project/tqdm/) for the CLI progress bar
- Tkinter (usually included with most Python installations)

## Installation

### General Steps

1. **Clone or Download this Repository.**
   ```bash
   git clone https://github.com/yourusername/file-encryption-tool.git
   cd file-encryption-tool
   ```

2. **Install Dependencies** (in a virtual environment is highly recommended).
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install pycryptodome tqdm
   ```

### macOS Ventura and PEP 668

On macOS Ventura (and potentially newer versions), **system Python** is marked as “externally managed” per [PEP 668](https://peps.python.org/pep-0668/). If you try to install packages system-wide using `pip3`, you may get an **`externally-managed-environment`** error.

To avoid this issue, you have two main approaches:

1. **Use a Virtual Environment** (preferred):  
   ```bash
   # Create and activate a virtual environment
   python3 -m venv venv
   source venv/bin/activate

   # Install packages into the venv
   pip install pycryptodome tqdm

   # Run your script in the venv
   python encryption_tool.py ...
   ```
   When you're finished, type `deactivate` to exit the virtual environment.

2. **Install a Separate Python via Homebrew**:  
   ```bash
   brew install python
   # This will install a separate python (e.g., /opt/homebrew/bin/python3 or /usr/local/bin/python3)

   /opt/homebrew/bin/python3 -m venv venv
   source venv/bin/activate
   pip install pycryptodome tqdm
   ```
   This ensures you don’t conflict with Apple’s system-managed Python.

> **Note:** You can also force `pip` to install in the system environment with `--break-system-packages`, but **this is strongly discouraged** as it may cause conflicts or break the system-managed Python.

## Usage

Once dependencies are installed (in your virtual environment or separate Python), you can run the tool in **GUI mode** or **CLI mode**:

### 1. GUI Mode

Open the Tkinter GUI with:

```bash
python encryption_tool.py gui
```

A window will appear where you can:
- **Browse** for a file.
- Enter a **Password**.
- Select **AES Mode** (`EAX` or `GCM`).
- Click **Encrypt** or **Decrypt**.

### 2. CLI Mode

You can also use the command-line interface for more advanced use cases.

```bash
python encryption_tool.py [command] [options]
```

**Commands**:

1. **encrypt**  
   Encrypt a file from the command line.  
   **Example**:  
   ```bash
   python encryption_tool.py encrypt -f secret.txt -p "MyStrongPassword" --mode GCM
   ```
   - **Options**:
     - `-o/--output` to specify the output file name (defaults to `secret.txt.enc`).
     - `-m/--mode` to choose AES mode (`EAX` or `GCM`).

2. **decrypt**  
   Decrypt a file from the command line.  
   **Example**:  
   ```bash
   python encryption_tool.py decrypt -f secret.txt.enc -p "MyStrongPassword"
   ```
   - **Options**:
     - `-o/--output` to specify the output file name (defaults to removing `.enc` extension or adding `.dec`).
     - `-m/--mode` to choose AES mode (`EAX` or `GCM`).

## Examples

1. **Encrypt a PDF (CLI)**:
   ```bash
   python encryption_tool.py encrypt -f report.pdf -p "MyPassword123" -m GCM
   # Outputs: report.pdf.enc
   ```

2. **Decrypt a PDF (CLI)**:
   ```bash
   python encryption_tool.py decrypt -f report.pdf.enc -p "MyPassword123" -m GCM
   # Outputs: report.pdf
   ```

3. **Launch the GUI**:
   ```bash
   python encryption_tool.py gui
   ```

## How It Works

1. **Key Generation**  
   A secure 256-bit key is derived from your provided password using **scrypt** with a random salt.

2. **AES Encryption (EAX/GCM)**  
   The tool uses either EAX or GCM mode for authenticated encryption. A **tag** is generated to verify integrity during decryption.

3. **Chunk-Based Processing (CLI)**  
   Large files are processed in 64KB chunks to avoid high memory usage, with `tqdm` providing real-time progress feedback.

## Contributing

Feel free to open pull requests or issues to add features (e.g., more ciphers, refined GUI, etc.).

## License

Distributed under the **MIT License**. See `LICENSE` for more information.
