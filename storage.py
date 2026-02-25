"""
storage.py – Password data storage and retrieval.

This module contains DataStorage, the single class responsible for all
file I/O related to stored passwords:

  - Reading the current password data (decrypting on the fly if needed).
  - Appending new entries (website / email / password) to the text store.
  - Keeping the Excel file in sync with the text store after every save.
  - Opening the text or Excel file with the OS default application.

DataStorage depends on AppConfig (for file paths and settings) and
CryptoManager (for transparent encrypt/decrypt of data on disk).

Validation logic is encapsulated in the EntryValidationError exception
so that the UI layer (AppWindow) can report problems without duplicating
validation rules.
"""

import logging
import os
import re
import subprocess
import sys
import tempfile
from typing import Optional

logger = logging.getLogger("PasswordManager")

# ---------------------------------------------------------------------------
# Optional openpyxl – Excel export is unavailable without it.
# ---------------------------------------------------------------------------
try:
    from openpyxl import Workbook
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False


class EntryValidationError(ValueError):
    """
    Raised by DataStorage.save_entry() when a field fails validation.

    Attributes
    ----------
    field : str or None
        The name of the field that caused the error ('website', 'email',
        or 'password').  Used by AppWindow to focus the correct Entry widget.
    """

    def __init__(self, message: str, field: Optional[str] = None) -> None:
        super().__init__(message)
        self.field: Optional[str] = field


class DataStorage:
    """
    Manages reading and writing of password data files.

    Parameters
    ----------
    config : AppConfig
        Provides file paths and runtime configuration values.
    crypto : CryptoManager
        Performs transparent encryption/decryption of data files.
    """

    def __init__(self, config, crypto) -> None:
        self.config = config
        self.crypto = crypto

    # ------------------------------------------------------------------
    # Reading data
    # ------------------------------------------------------------------

    def read_plain_txt_bytes(self) -> bytes:
        """
        Return the current password data as raw bytes.

        Reading strategy (in order of preference):
          1. If encryption is active and the encrypted file exists,
             decrypt it in memory and return the plaintext bytes.
          2. If a plaintext file exists, return its raw bytes.
          3. Return empty bytes when no data file is found at all.
        """
        cfg = self.config
        if (
            self.crypto.use_encryption
            and os.path.exists(cfg.data_txt_enc)
            and self.crypto.master_key
        ):
            try:
                with open(cfg.data_txt_enc, "rb") as fh:
                    return self.crypto.decrypt_bytes(fh.read())
            except Exception:
                logger.exception("Failed to read/decrypt encrypted text data")
                return b""

        if os.path.exists(cfg.data_txt):
            try:
                with open(cfg.data_txt, "rb") as fh:
                    return fh.read()
            except Exception:
                logger.exception("Failed to read plaintext data file")
                return b""

        return b""

    # ------------------------------------------------------------------
    # Writing data
    # ------------------------------------------------------------------

    def save_entry(self, website: str, email: str, password: str) -> None:
        """
        Validate the three fields and append a new record to the data store.

        The record is written as a tab-separated line to the text file and
        the Excel export is regenerated immediately afterwards.

        Raises
        ------
        EntryValidationError
            If any field is missing or the email address is not valid.
            The 'field' attribute of the exception names the offending
            field so that AppWindow can set focus to the right Entry widget.
        """
        # --- Validate inputs ---
        if not website:
            raise EntryValidationError("Website field cannot be empty.", field="website")
        if not email:
            raise EntryValidationError("Email field cannot be empty.", field="email")
        if not self._validate_email(email):
            raise EntryValidationError("Email address is not valid.", field="email")
        if not password:
            raise EntryValidationError("Password field cannot be empty.", field="password")

        # --- Build the new line and merge with existing data ---
        new_line = f"{website}\t{email}\t{password}\n"
        existing = self.read_plain_txt_bytes()
        header = "Website\tEmail\tPassword\n".encode("utf-8")

        if not existing.strip():
            # No data yet: write header + first record.
            new_data = header + new_line.encode("utf-8")
        elif not existing.decode("utf-8", errors="ignore").lstrip().lower().startswith("website"):
            # Data exists but the header line is missing: prepend it.
            new_data = header + existing + new_line.encode("utf-8")
        else:
            # Normal case: append to existing data.
            new_data = existing + new_line.encode("utf-8")

        # --- Persist the text store ---
        self._write_txt(new_data)

        # --- Keep Excel in sync ---
        try:
            self.write_excel_from_text(new_data)
        except Exception:
            logger.exception("Failed to update Excel file after saving entry")

    def _write_txt(self, data: bytes) -> None:
        """
        Write *data* to the text password store.

        If encryption is active, the data is encrypted with the master key
        and stored as data.txt.enc; any leftover plaintext file is removed.
        Otherwise the data is written as a plaintext file; any leftover
        encrypted file is removed.
        """
        cfg = self.config
        if self.crypto.use_encryption and self.crypto.master_key:
            # Write encrypted file and remove any plaintext copy.
            self.crypto.encrypt_bytes_to_file(data, cfg.data_txt_enc)
            self._silent_remove(cfg.data_txt)
        else:
            # Write plaintext file and remove any encrypted copy.
            with open(cfg.data_txt, "wb") as fh:
                fh.write(data)
            self._silent_remove(cfg.data_txt_enc)

    def write_excel_from_text(self, data_bytes: bytes) -> bool:
        """
        Build (or overwrite) the Excel file from tab-separated *data_bytes*.

        Expected format: one row per line with columns
        Website<TAB>Email<TAB>Password.  An optional header row is detected
        and excluded from the data rows (it is always re-added as the first
        Excel row).

        Column widths are read from the 'excel_column_widths' config entry.

        If encryption is active, the Excel file is written to a temporary
        location, read back as bytes, encrypted and stored as data.xlsx.enc.
        Otherwise the .xlsx file is written directly.

        Returns True on success; False when openpyxl is unavailable or
        an error occurs.
        """
        if not EXCEL_AVAILABLE or not data_bytes:
            return False

        try:
            text = data_bytes.decode("utf-8", errors="replace")
            lines = [ln for ln in text.splitlines() if ln.strip()]

            # Detect and skip a header row if present.
            data_lines = lines
            if lines:
                first = lines[0].strip().lower()
                if "website" in first and "email" in first and "password" in first:
                    data_lines = lines[1:]

            # Parse each line into exactly three columns.
            rows = []
            for ln in data_lines:
                parts = ln.split("\t")
                while len(parts) < 3:
                    parts.append("")
                rows.append(parts[:3])

            # Build the workbook.
            wb = Workbook()
            ws = wb.active
            ws.title = "Passwords"
            ws.append(["Website", "Email", "Password"])  # always write header
            for row in rows:
                ws.append(row)

            # Apply column widths from config (best-effort).
            try:
                widths = self.config.get("excel_column_widths", {"A": 30, "B": 30, "C": 30})
                for col, width in widths.items():
                    if col in ("A", "B", "C"):
                        ws.column_dimensions[col].width = int(width)
            except Exception:
                pass

            # Write the workbook (encrypted or plaintext).
            cfg = self.config
            if self.crypto.use_encryption and self.crypto.master_key:
                # Save to a temp file first, then encrypt the bytes.
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx")
                tmp_path = tmp.name
                tmp.close()
                try:
                    wb.save(tmp_path)
                    with open(tmp_path, "rb") as fh:
                        xlsx_bytes = fh.read()
                    self.crypto.encrypt_bytes_to_file(xlsx_bytes, cfg.data_xlsx_enc)
                    self._silent_remove(cfg.data_xlsx)
                finally:
                    self._silent_remove(tmp_path)
            else:
                wb.save(cfg.data_xlsx)
                self._silent_remove(cfg.data_xlsx_enc)

            return True

        except Exception:
            logger.exception("Failed to build Excel file from text data")
            return False

    # ------------------------------------------------------------------
    # Opening files with the OS default application
    # ------------------------------------------------------------------

    def open_with_default_app(self, path: str) -> None:
        """
        Open *path* using the operating-system default application for its
        file type (e.g. Notepad for .txt, Excel for .xlsx).

        Shows a warning dialog if the file cannot be opened.
        """
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)                   # Windows
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])      # macOS
            else:
                subprocess.Popen(["xdg-open", path])  # Linux / other POSIX
        except Exception:
            from tkinter import messagebox
            logger.exception("Failed to open file: %s", path)
            messagebox.showwarning("Open failed", f"Could not open:\n{path}")

    def open_txt(self) -> None:
        """
        Decrypt (if needed) and open the text password file with the default
        text editor.

        Shows an info dialog if no data file is currently available.
        """
        from tkinter import messagebox
        cfg = self.config

        if (
            self.crypto.use_encryption
            and os.path.exists(cfg.data_txt_enc)
            and self.crypto.master_key
        ):
            # Decrypt to a temporary file and open that.
            temp_path = self.crypto.decrypt_file_to_temp(cfg.data_txt_enc)
            self.open_with_default_app(temp_path)
        elif os.path.exists(cfg.data_txt):
            self.open_with_default_app(cfg.data_txt)
        else:
            messagebox.showinfo("No data", "No text data file is available yet.")

    def open_excel(self) -> None:
        """
        Decrypt (if needed) and open the Excel password file.

        If the Excel file does not exist yet but text data is available,
        the method attempts to generate the Excel file on demand before
        opening it.

        Shows an info dialog if no data is available at all.
        """
        from tkinter import messagebox
        cfg = self.config

        # Encrypted Excel file exists – decrypt and open.
        if (
            self.crypto.use_encryption
            and os.path.exists(cfg.data_xlsx_enc)
            and self.crypto.master_key
        ):
            temp_path = self.crypto.decrypt_file_to_temp(cfg.data_xlsx_enc)
            self.open_with_default_app(temp_path)
            return

        # Plaintext Excel file exists – open directly.
        if os.path.exists(cfg.data_xlsx):
            self.open_with_default_app(cfg.data_xlsx)
            return

        # No Excel file yet – try to generate it from the text data.
        txt_bytes = self.read_plain_txt_bytes()
        if txt_bytes and EXCEL_AVAILABLE:
            ok = self.write_excel_from_text(txt_bytes)
            if ok:
                # Open whichever file was just written.
                if (
                    self.crypto.use_encryption
                    and os.path.exists(cfg.data_xlsx_enc)
                    and self.crypto.master_key
                ):
                    temp_path = self.crypto.decrypt_file_to_temp(cfg.data_xlsx_enc)
                    self.open_with_default_app(temp_path)
                elif os.path.exists(cfg.data_xlsx):
                    self.open_with_default_app(cfg.data_xlsx)
                return

        messagebox.showinfo("No data", "No Excel data file is available yet.")

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_email(email: str) -> bool:
        """
        Return True if *email* looks like a syntactically valid e-mail
        address (simple regex check: non-empty local part, @ sign, domain
        with at least one dot).
        """
        if not email or "@" not in email:
            return False
        return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

    @staticmethod
    def _silent_remove(path: str) -> None:
        """
        Remove *path* without raising an exception if the file does not
        exist or the deletion fails.  Used to clean up stale plaintext or
        encrypted files after a transition.
        """
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
