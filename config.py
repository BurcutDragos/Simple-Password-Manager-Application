"""
config.py – Application configuration and constants.

This module defines AppConfig, a central container for:
  - All application-wide constants (font names, colour codes, size limits, etc.)
  - The user configuration (auto-copy, clipboard timeout, …) stored as a JSON
    file on disk and exposed through a simple dict-like interface.
  - Helper utilities shared across modules: OS-appropriate data-directory
    resolution, PyInstaller-aware resource-path resolution, and logger setup.

No other application module is imported here, so config.py sits at the bottom
of the dependency graph and can be safely imported by any other module.
"""

import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

# ---------------------------------------------------------------------------
# Optional third-party library – appdirs provides the OS-standard user-data
# directory (e.g. %APPDATA%\PasswordManager on Windows).
# ---------------------------------------------------------------------------
try:
    import appdirs
    _APPDIRS_AVAILABLE = True
except ImportError:
    _APPDIRS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Application-level constants – these never change at runtime.
# ---------------------------------------------------------------------------

APP_NAME = "PasswordManager"

# Human-readable application version shown in the About dialog.
APP_VERSION = "1.0.0"

# Minimum number of characters in a generated password.
MIN_LENGTH = 12

# Special characters available for generated passwords.
SYMBOLS = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

# Minimum pixel width of the scrollable content area.
# The horizontal scroll-bar appears when the window is narrower than this.
MIN_CONTENT_WIDTH = 620

# Fallback character-width for Entry widgets (used when pixel width is unknown).
ENTRY_MIN_CHARS = 30

# ---------------------------------------------------------------------------
# Default values written to config.json on first run.
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: dict = {
    # Automatically copy a newly generated password to the clipboard.
    "auto_copy_generated": True,
    # Seconds before the clipboard is cleared after a copy (0 = never clear).
    "clipboard_clear_seconds": 20,
    # Column widths (in characters) for the exported Excel file.
    "excel_column_widths": {"A": 30, "B": 30, "C": 30},
}


class AppConfig:
    """
    Manages application configuration, file paths and logging.

    On instantiation the class:
      1. Resolves the OS-appropriate user-data directory.
      2. Derives all relevant file paths from that directory.
      3. Sets up a rotating log handler.
      4. Loads (or creates) the JSON configuration file.

    Attributes
    ----------
    user_data_dir : str
        Absolute path of the directory that stores all persistent data.
    data_txt : str
        Plaintext tab-separated password file.
    data_xlsx : str
        Plaintext Excel password file.
    data_csv : str
        Plaintext CSV password file (reserved for future use).
    data_txt_enc : str
        Encrypted counterpart of data_txt (Fernet ciphertext).
    data_xlsx_enc : str
        Encrypted counterpart of data_xlsx.
    data_csv_enc : str
        Encrypted counterpart of data_csv.
    salt_path : str
        16-byte random salt used for PBKDF2 key derivation.
    keycheck_path : str
        Small Fernet token used to verify the master password at login.
    config_path : str
        JSON configuration file.
    log_path : str
        Rotating application log.
    data : dict
        The currently loaded configuration values (mutable at runtime).
    logger : logging.Logger
        Shared Python logger for the whole application.
    """

    def __init__(self) -> None:
        # --- Resolve (and create) the persistent data directory ---
        self.user_data_dir: str = self._get_user_data_dir()

        # --- Derive all file paths from the data directory ---
        self.data_txt:      str = os.path.join(self.user_data_dir, "data.txt")
        self.data_xlsx:     str = os.path.join(self.user_data_dir, "data.xlsx")
        self.data_csv:      str = os.path.join(self.user_data_dir, "data.csv")
        self.data_txt_enc:  str = self.data_txt  + ".enc"
        self.data_xlsx_enc: str = self.data_xlsx + ".enc"
        self.data_csv_enc:  str = self.data_csv  + ".enc"
        self.salt_path:     str = os.path.join(self.user_data_dir, "salt.bin")
        self.keycheck_path: str = os.path.join(self.user_data_dir, "keycheck.bin")
        self.config_path:   str = os.path.join(self.user_data_dir, "config.json")
        self.log_path:      str = os.path.join(self.user_data_dir, "app.log")

        # --- Configure the rotating log handler ---
        self.logger: logging.Logger = self._setup_logger()

        # --- Load or create the JSON configuration ---
        self.data: dict = self._load()

        self.logger.info("AppConfig initialised; data dir: %s", self.user_data_dir)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_user_data_dir() -> str:
        """
        Return (and create if necessary) the OS-appropriate user-data
        directory.

        Uses *appdirs* when available; falls back to APPDATA on Windows
        and ~/.local/share on POSIX systems.
        """
        if _APPDIRS_AVAILABLE:
            path = appdirs.user_data_dir(APP_NAME)
        elif sys.platform.startswith("win"):
            appdata = os.getenv("APPDATA") or os.path.expanduser("~")
            path = os.path.join(appdata, APP_NAME)
        else:
            path = os.path.expanduser(os.path.join("~", ".local", "share", APP_NAME))

        os.makedirs(path, exist_ok=True)
        return path

    def _setup_logger(self) -> logging.Logger:
        """
        Create and configure a rotating file logger for the whole application.

        The log rotates at 2 MB and keeps up to 3 backup files.
        Duplicate handlers are avoided if the logger already exists
        (e.g. on module reload during development).
        """
        logger = logging.getLogger(APP_NAME)
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            handler = RotatingFileHandler(
                self.log_path,
                maxBytes=2_000_000,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
            )
            logger.addHandler(handler)

        return logger

    def _load(self) -> dict:
        """
        Read config.json from disk.

        Missing keys are back-filled from DEFAULT_CONFIG so that new
        settings introduced in later versions are always present.
        Encryption is unconditionally forced to True regardless of whatever
        was previously written to disk.

        Returns the loaded (or default) configuration dictionary.
        """
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, "r", encoding="utf-8") as fh:
                    cfg: dict = json.load(fh)
                # Ensure any newly added keys are present
                for key, value in DEFAULT_CONFIG.items():
                    cfg.setdefault(key, value)
                cfg["use_encryption"] = True  # always enforce encryption
                return cfg
        except Exception:
            self.logger.exception("Failed to load config; using defaults")

        # Fallback: return a fresh copy of the defaults
        cfg = dict(DEFAULT_CONFIG)
        cfg["use_encryption"] = True
        return cfg

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Persist the current configuration dictionary to disk as JSON."""
        try:
            with open(self.config_path, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2)
            self.logger.info("Config saved")
        except Exception:
            self.logger.exception("Failed to save config")

    def get(self, key: str, default=None):
        """Return a configuration value by key, or *default* if not found."""
        return self.data.get(key, default)

    def set(self, key: str, value) -> None:
        """
        Update a configuration value in memory.

        Call save() afterwards to persist the change to disk.
        """
        self.data[key] = value

    @staticmethod
    def resource_path(rel_path: str) -> str:
        """
        Resolve *rel_path* to an absolute path that works both in the
        normal development environment and inside a PyInstaller bundle.

        PyInstaller extracts bundled resources to a temporary directory
        stored in sys._MEIPASS at runtime.
        """
        try:
            base = sys._MEIPASS  # type: ignore[attr-defined]  # set by PyInstaller
        except AttributeError:
            base = os.path.abspath(".")
        return os.path.join(base, rel_path)