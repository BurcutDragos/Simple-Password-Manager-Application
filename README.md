# Simple-Password-Manager-Application

A secure, cross-platform desktop password manager built with Python and Tkinter. All stored credentials are protected by strong Fernet encryption (AES-128-CBC + HMAC-SHA256) derived from a user-chosen master password, so your data is always encrypted at rest and never stored in plain text.

## 📱 Key Features:
- **Master Password Protection**: Every session is secured by a master password. A PBKDF2-HMAC-SHA256 key derivation function (390 000 iterations) derives the encryption key from your password and a random salt — the master password itself is never stored anywhere.
- **Fernet Encryption**: All password data and exports are encrypted with the `cryptography` library's Fernet scheme (AES-128-CBC + HMAC-SHA256), ensuring both confidentiality and integrity of stored files.
- **Password Generator**: Instantly generate strong, random passwords composed of uppercase and lowercase letters, digits and special characters, with an optional one-click copy to the system clipboard.
- **Text & Excel Export**: View your stored credentials in a plain-text file or a formatted Excel spreadsheet (`.xlsx`). Files are decrypted to a temporary location, opened with the OS default application, and the temporary copy is deleted automatically on exit.
- **Recovery File**: Create an encrypted recovery file protected by a separate passphrase. If you ever forget your master password, the recovery file lets you reset it and re-encrypt all your data without losing anything.
- **Change Master Password**: Change your master password at any time. All encrypted files are atomically re-encrypted with the new key — backups are created before every write so no data is ever lost mid-operation.
- **Factory Reset**: Safely wipe all local application data. Every affected file is moved to a timestamped backup folder before deletion, giving you a safety net if you change your mind.
- **Responsive, Scrollable UI**: A clean Tkinter interface with a scrollable canvas that adapts gracefully to any window size, with horizontal and vertical scroll-bars appearing only when needed.

## ✅ Project Structure:

This repository includes:
- `main.py` — Application entry point; instantiates `AppWindow` and starts the event loop
- `config.py` — Application-wide constants (`APP_NAME`, `APP_VERSION`, colour tokens, etc.), OS-aware user-data directory resolution, rotating file logger setup, and JSON config load/save (`AppConfig`)
- `crypto.py` — All cryptographic operations: PBKDF2 key derivation, salt and key-check file management, Fernet encrypt/decrypt, temporary decrypted-file tracking, recovery file creation and restoration, and atomic re-encryption of data files (`CryptoManager`)
- `storage.py` — Password file I/O (read/write encrypted or plain text), on-demand Excel generation, and opening files with the OS default application (`DataStorage`, `EntryValidationError`)
- `auth.py` — Every authentication-related dialog: first-run setup, login (unlock / restore from recovery / factory reset / exit), master password change, recovery file creation, and factory reset confirmation (`AuthManager`)
- `ui.py` — Complete Tkinter UI: scrollable canvas, header with logo and action buttons, input form, action row, settings panel, and all event handlers (`AppWindow`)
- `padlock.png` — Application icon shown in the window title bar and header
- `requirements.txt` — Python package dependencies
- `README.md` — This documentation file
- `LICENSE` — Project license

## ❌ Not Included (Git-Ignored):

According to the `.gitignore` file, the following folders/files are excluded and **not uploaded** to GitHub:
- `.venv/` — Local Python virtual environment (created during setup; not portable across machines)
- `__pycache__/`, `*.pyc`, `*.pyo` — Python bytecode cache files auto-generated at runtime
- `dist/`, `build/`, `*.spec` — PyInstaller output folders and spec files generated when packaging a standalone executable
- `.vs/`, `.idea/`, `*.egg-info/` — IDE-specific project files and metadata folders
- User data directory (`%APPDATA%\PasswordManager\` on Windows, `~/.local/share/PasswordManager/` on Linux/macOS) — Contains all encrypted password files (`data.txt.enc`, `data.xlsx.enc`), the salt (`salt.bin`), the key-check token (`keycheck.bin`), the application config (`config.json`), the rotating log (`app.log`), and any recovery backups. This directory lives **outside** the project folder and is never part of the repository.

## 🚀 How to Open and Run the Project Locally:

To successfully set up and run this project on your machine, follow the steps below:

### 1. Prerequisites:
- **Python 3.10 or newer** — Download from [python.org](https://www.python.org/downloads/)
- **pip** — Included with Python; used to install dependencies
- **Git** — Download from [git-scm.com](https://git-scm.com/)
- **An integrated development environment** that supports Python (Visual Studio Code, PyCharm, Notepad++, etc.)

Required Python packages (installed in step 5):
- **`cryptography`** *(required)* — Fernet encryption and PBKDF2 key derivation
- **`openpyxl`** *(optional)* — Excel export; the app works without it but `.xlsx` files cannot be generated
- **`pyperclip`** *(optional)* — System clipboard access for the auto-copy feature
- **`appdirs`** *(optional)* — OS-standard user-data directory resolution; falls back to `APPDATA` / `~/.local/share` if absent

> 📌 Python 3.10 or newer is required because the project uses union-type annotations (`X | Y`) and other modern language features. The application will not start on older Python versions.

### 2. Clone the Repository:
```bash
git clone https://github.com/BurcutDragos/Simple-Password-Manager-Application.git
```

### 3. Navigate to the Project Directory:
```bash
cd Simple-Password-Manager-Application
```

### 4. Create and Activate a Virtual Environment:

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

> 📌 Using a virtual environment is strongly recommended so that the project's dependencies do not interfere with other Python projects on your system.

### 5. Install Dependencies:
```bash
pip install -r requirements.txt
```

To install only the required package (minimum setup):
```bash
pip install cryptography
```

### 6. Run the Application:
```bash
python main.py
```

On first launch you will be prompted to create a master password. This password is used to derive the encryption key for all stored data — **write it down and keep it safe**. If you forget it, you can only recover your data with a previously created recovery file.

## 🧠 Notes:
- The **`cryptography`** package is **mandatory**. The application will display an error and exit if it is not installed.
- All encrypted files are stored in the OS user-data directory (`%APPDATA%\PasswordManager\` on Windows, `~/.local/share/PasswordManager/` on Linux/macOS). This directory is created automatically on first run.
- The **master password is never saved** to disk. Only a random 16-byte salt and a small Fernet-encrypted verification token (`keycheck.bin`) are stored — solely to confirm that the entered password is correct at login.
- **Recovery files** should be saved offline (USB drive, secure cloud storage) and kept completely separate from the computer that holds your encrypted data.
- Temporary decrypted files created when opening a `.txt` or `.xlsx` view are stored in the system temp directory and are deleted automatically when the application closes.
- The application log (`app.log`) is a rotating file (max 2 MB, 3 backups) located in the user-data directory and can be used to diagnose any issues.

## 🤝 Contributing:
1. Fork the repository.
2. Create a new branch: `git checkout -b my-feature-branch`
3. Make your changes and commit them: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin my-feature-branch`
5. Submit a pull request.

## 📄 License:
This project is licensed under the MIT License - see the LICENSE file for details.

## 🧑‍💻 Author(s):
Burcut Ioan Dragos.

## 💡 Acknowledgments:
Thanks to Anthropic (Claude AI) for providing assistance in the development of this project.
