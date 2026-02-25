"""
main.py – Application entry point.

This file is intentionally minimal.  All logic lives in specialised modules:

  config.py   – AppConfig      : constants, file paths, config I/O, logging
  crypto.py   – CryptoManager  : key derivation, Fernet encrypt/decrypt,
                                  recovery files, atomic re-encryption
  storage.py  – DataStorage    : password file I/O, Excel export,
                                  open files with default OS application
  auth.py     – AuthManager    : master-password dialogs, recovery flow,
                                  password change, factory reset
  ui.py       – AppWindow      : complete Tkinter UI, all event handlers

To run the application:
    python main.py

To build a standalone executable (requires PyInstaller):
    pyinstaller --onefile --windowed --add-data "padlock.png;." main.py
"""

from ui import AppWindow


def main() -> None:
    """Create the application window and start the event loop."""
    app = AppWindow()
    app.run()


if __name__ == "__main__":
    main()
