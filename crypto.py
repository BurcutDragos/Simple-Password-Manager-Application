"""
crypto.py – Cryptographic operations for the Password Manager.

This module contains CryptoManager, which is the single place responsible
for every cryptographic concern in the application:

  - Key derivation from the master password using PBKDF2-HMAC-SHA256.
  - Salt and key-check file management (used to verify the password at login).
  - Encrypting and decrypting byte streams with Fernet
    (AES-128-CBC + HMAC-SHA256, provided by the 'cryptography' package).
  - Creating and reading recovery files (master key wrapped with a separate
    key derived from a recovery passphrase).
  - Atomically re-encrypting all data files when the master password changes
    (rewrap_encrypted_files).
  - Managing a list of temporary decrypted files that must be removed on exit.

If the 'cryptography' package is not installed, CRYPTO_AVAILABLE is False
and all CryptoManager methods that actually need crypto raise RuntimeError.
The application requires the package; this is enforced by AuthManager at
startup.
"""

import base64
import json
import logging
import os
import shutil
import tempfile
from typing import List, Optional

logger = logging.getLogger("PasswordManager")

# ---------------------------------------------------------------------------
# Optional cryptography library
# ---------------------------------------------------------------------------
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class CryptoManager:
    """
    Handles all cryptographic operations for the Password Manager.

    Parameters
    ----------
    config : AppConfig
        Application configuration object used for file paths and logging.

    Attributes
    ----------
    available : bool
        True when the 'cryptography' package was successfully imported.
    master_key : bytes or None
        The derived Fernet key (URL-safe base64-encoded, 32 raw bytes).
        None until the user successfully authenticates via AuthManager.
    use_encryption : bool
        True when encryption is both available and actively in use.
    """

    def __init__(self, config) -> None:
        self.config = config

        # Whether the cryptography package is present on this system.
        self.available: bool = CRYPTO_AVAILABLE

        # Set to a Fernet-compatible key (bytes) by AuthManager after login.
        self.master_key: Optional[bytes] = None

        # Encryption is active only when the library is available.
        # AuthManager may set this to False after a factory reset.
        self.use_encryption: bool = CRYPTO_AVAILABLE

        # Paths of temporary plaintext files created during this session.
        # They are deleted by cleanup_temp_files() on application exit.
        self._temp_files: List[str] = []

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a 32-byte Fernet-compatible key from *password* and *salt*
        using PBKDF2-HMAC-SHA256 with 390 000 iterations.

        The raw 32 bytes are URL-safe base64-encoded so they can be passed
        directly to Fernet().

        Raises RuntimeError if the 'cryptography' package is not installed.
        """
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("'cryptography' package is not installed")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390_000,
            backend=default_backend(),
        )
        raw_key = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw_key)

    # ------------------------------------------------------------------
    # Salt management
    # ------------------------------------------------------------------

    def create_and_store_salt(self) -> bytes:
        """
        Generate a new cryptographically-random 16-byte salt, write it
        to the salt file defined in config.salt_path, and return it.

        Called once on first run when the user creates a master password.
        """
        salt = os.urandom(16)
        with open(self.config.salt_path, "wb") as fh:
            fh.write(salt)
        return salt

    def load_salt(self) -> Optional[bytes]:
        """
        Read and return the salt from disk.

        Returns None when the salt file does not exist, which signals a
        first-run or post-factory-reset state (no existing encrypted data).
        """
        if os.path.exists(self.config.salt_path):
            with open(self.config.salt_path, "rb") as fh:
                return fh.read()
        return None

    # ------------------------------------------------------------------
    # Key-check file
    # ------------------------------------------------------------------

    def create_keycheck_file(self, fernet: "Fernet") -> None:
        """
        Encrypt a known plaintext token (b"keycheck") with *fernet* and
        store the ciphertext in config.keycheck_path.

        verify_master_password() later decrypts this token to confirm that
        the provided password is correct without exposing the actual data.
        """
        token = fernet.encrypt(b"keycheck")
        with open(self.config.keycheck_path, "wb") as fh:
            fh.write(token)

    def verify_master_password(self, password: str) -> bool:
        """
        Return True if *password* correctly decrypts the key-check file.

        Returns False on any error: wrong password, missing salt/keycheck
        file, or corrupted data.
        """
        salt = self.load_salt()
        if salt is None:
            return False
        try:
            key = self.derive_key(password, salt)
            fernet = Fernet(key)
            with open(self.config.keycheck_path, "rb") as fh:
                ciphertext = fh.read()
            plaintext = fernet.decrypt(ciphertext)
            return plaintext == b"keycheck"
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Encrypt / decrypt helpers
    # ------------------------------------------------------------------

    def encrypt_bytes_to_file(self, data: bytes, out_path: str) -> None:
        """
        Encrypt *data* with the current master key and write the ciphertext
        to *out_path*.

        Raises RuntimeError if no master key is set.
        """
        if not self.master_key:
            raise RuntimeError("No master key is set – cannot encrypt.")
        fernet = Fernet(self.master_key)
        with open(out_path, "wb") as fh:
            fh.write(fernet.encrypt(data))

    def decrypt_bytes(self, enc_bytes: bytes) -> bytes:
        """
        Decrypt *enc_bytes* with the current master key and return the
        plaintext as bytes.

        Raises RuntimeError if no master key is set.
        Raises cryptography.fernet.InvalidToken on wrong key or corrupted data.
        """
        if not self.master_key:
            raise RuntimeError("No master key is set – cannot decrypt.")
        fernet = Fernet(self.master_key)
        return fernet.decrypt(enc_bytes)

    def decrypt_file_to_temp(self, encrypted_path: str) -> str:
        """
        Decrypt *encrypted_path* to a temporary file that preserves the
        original extension (e.g. 'data.txt.enc' → a temp file ending in .txt).

        The temporary file is registered in _temp_files so it is deleted
        automatically when the application closes (via cleanup_temp_files).

        Returns the absolute path to the temporary plaintext file.
        """
        with open(encrypted_path, "rb") as fh:
            enc_bytes = fh.read()
        plaintext = self.decrypt_bytes(enc_bytes)

        # Determine the correct plaintext extension from the encrypted extension.
        extension_map = {
            ".txt.enc":  ".txt",
            ".xlsx.enc": ".xlsx",
            ".csv.enc":  ".csv",
        }
        ext = ""
        for enc_ext, plain_ext in extension_map.items():
            if encrypted_path.endswith(enc_ext):
                ext = plain_ext
                break

        # Write decrypted bytes to a named temporary file.
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
        tmp.write(plaintext)
        tmp.close()
        self._temp_files.append(tmp.name)
        return tmp.name

    def cleanup_temp_files(self) -> None:
        """
        Delete all temporary decrypted files created during this session.

        This method is registered with atexit so it is also called
        automatically when the Python process exits.
        """
        for path in list(self._temp_files):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                logger.exception("Failed to remove temp file %s", path)
        self._temp_files.clear()

    # ------------------------------------------------------------------
    # Recovery file – creation and key retrieval
    # ------------------------------------------------------------------

    def create_recovery_file(self, out_path: str, recovery_passphrase: str) -> bool:
        """
        Wrap the current master key with a key derived from
        *recovery_passphrase* and save the result as a JSON file at
        *out_path*.

        The recovery file format:
          {
            "version": 1,
            "kdf_salt": "<base64-encoded 16-byte salt>",
            "encrypted_master_key": "<base64-encoded Fernet ciphertext>"
          }

        The recovery file can later be used with restore_from_recovery_file()
        to regain access when the master password is forgotten.

        Returns True on success; False on any error.
        """
        if not self.master_key:
            raise RuntimeError("No master key is set – cannot create recovery file.")
        try:
            # Derive a separate key for the recovery passphrase (fewer
            # iterations than the main key because the file is kept offline).
            rec_salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=rec_salt,
                iterations=200_000,
                backend=default_backend(),
            )
            rec_key = base64.urlsafe_b64encode(
                kdf.derive(recovery_passphrase.encode("utf-8"))
            )
            fernet = Fernet(rec_key)

            # The master_key is already URL-safe base64 bytes; encrypt as-is.
            encrypted_master = fernet.encrypt(self.master_key)

            payload = {
                "version": 1,
                "kdf_salt": base64.b64encode(rec_salt).decode("utf-8"),
                "encrypted_master_key": base64.b64encode(encrypted_master).decode("utf-8"),
            }
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            return True
        except Exception:
            logger.exception("Failed to create recovery file")
            return False

    def restore_from_recovery_file(
        self, recovery_file_path: str, recovery_passphrase: str
    ) -> Optional[bytes]:
        """
        Read *recovery_file_path*, derive the recovery key from
        *recovery_passphrase*, and return the old master key bytes.

        Returns None if the file is unreadable, the passphrase is wrong,
        or any other error occurs.

        Important: this method does NOT modify self.master_key.
        The caller (AuthManager) handles the full reset flow including
        verification, re-encryption, and updating self.master_key.
        """
        try:
            with open(recovery_file_path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)

            rec_salt = base64.b64decode(payload["kdf_salt"])
            enc_master = base64.b64decode(payload["encrypted_master_key"])

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=rec_salt,
                iterations=200_000,
                backend=default_backend(),
            )
            rec_key = base64.urlsafe_b64encode(
                kdf.derive(recovery_passphrase.encode("utf-8"))
            )
            fernet = Fernet(rec_key)
            # decrypt() raises InvalidToken if the passphrase is wrong.
            old_master_key = fernet.decrypt(enc_master)
            return old_master_key
        except Exception:
            logger.exception("Failed to decrypt recovery file")
            return None

    # ------------------------------------------------------------------
    # Atomic re-encryption of all data files
    # ------------------------------------------------------------------

    def rewrap_encrypted_files(self, old_key: bytes, new_key: bytes) -> bool:
        """
        Re-encrypt every existing encrypted data file from *old_key* to
        *new_key* using a three-phase atomic strategy:

          Phase 1 – Create *.bak* backups of all existing encrypted files.
          Phase 2 – Decrypt with old_key, re-encrypt with new_key, and write
                    the result to *.tmp* companions (never overwriting originals
                    in this phase).
          Phase 3 – Atomically replace originals with their *.tmp* versions
                    using os.replace().

        If any phase fails, backups are restored and all *.tmp* files are
        removed so the original encrypted files remain intact.

        Returns True on complete success; False if any file could not be
        re-encrypted (originals are restored on failure).
        """
        enc_files = [
            self.config.data_txt_enc,
            self.config.data_xlsx_enc,
            self.config.data_csv_enc,
        ]

        tmp_paths: dict = {}  # original path -> .tmp path
        bak_paths: dict = {}  # original path -> .bak path

        def _restore_and_cleanup() -> None:
            """Best-effort rollback: restore .bak files and remove .tmp files."""
            for orig, bak in bak_paths.items():
                try:
                    shutil.copy2(bak, orig)
                except Exception:
                    logger.exception("Failed to restore backup %s -> %s", bak, orig)
            for tmp in tmp_paths.values():
                try:
                    os.remove(tmp)
                except Exception:
                    pass

        try:
            # --- Phase 1: create backups ---
            for enc_path in enc_files:
                if os.path.exists(enc_path):
                    bak = enc_path + ".bak"
                    shutil.copy2(enc_path, bak)
                    bak_paths[enc_path] = bak

            # --- Phase 2: decrypt with old key, re-encrypt with new key ---
            for enc_path in enc_files:
                if not os.path.exists(enc_path):
                    continue

                with open(enc_path, "rb") as fh:
                    enc_blob = fh.read()

                try:
                    plaintext = Fernet(old_key).decrypt(enc_blob)
                except InvalidToken:
                    # The old key does not match this file – abort entirely.
                    logger.error(
                        "InvalidToken while re-encrypting %s – aborting", enc_path
                    )
                    _restore_and_cleanup()
                    return False

                new_enc = Fernet(new_key).encrypt(plaintext)
                tmp = enc_path + ".tmp"
                with open(tmp, "wb") as out:
                    out.write(new_enc)
                tmp_paths[enc_path] = tmp

            # --- Phase 3: atomically replace originals with .tmp files ---
            for orig, tmp in tmp_paths.items():
                os.replace(tmp, orig)

            return True

        except Exception:
            logger.exception("Unexpected error during re-encryption")
            _restore_and_cleanup()
            return False
