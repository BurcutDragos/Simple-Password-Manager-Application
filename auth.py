"""
auth.py – Authentication and master-password management.

This module contains AuthManager, which drives every user-facing
authentication flow in the application:

  - First run: guide the user through creating a master password.
  - Subsequent runs: show a login dialog with options to unlock, restore
    from a recovery file, perform a factory reset, or exit.
  - Recovery: restore the master key from a previously created recovery file,
    prompt for a new master password, and re-encrypt all data files.
  - Password change: verify the current password, ask for a new one, and
    re-encrypt all data files atomically.
  - Recovery-file creation: wrap the master key with a user-supplied
    passphrase and save the result to a location chosen by the user.
  - Factory reset: move all application files to a timestamped backup folder
    and disable encryption so a fresh start can be made.

AuthManager depends on CryptoManager (low-level crypto primitives) and
AppConfig (file paths, config persistence) but never touches Tkinter widget
layout itself – all visual logic is in ui.py.  Dialog calls (messagebox,
simpledialog, filedialog, Toplevel) are confined to this module.
"""

import logging
import os
import shutil
import sys
import time
from tkinter import (
    Entry, Label, StringVar, Toplevel, messagebox, simpledialog, filedialog, ttk
)
from typing import Optional, Tuple

logger = logging.getLogger("PasswordManager")


class AuthManager:
    """
    Manages all authentication-related user-interface flows.

    Parameters
    ----------
    root : tk.Tk
        The main application window; used as the parent for every modal
        dialog so they stay centred and grab focus correctly.
    config : AppConfig
        Application configuration and file-path provider.
    crypto : CryptoManager
        Low-level cryptographic primitives (key derivation, encrypt, decrypt).
    storage : DataStorage
        Provides the encrypted-file paths needed for factory reset.
    """

    def __init__(self, root, config, crypto, storage) -> None:
        self.root    = root
        self.config  = config
        self.crypto  = crypto
        self.storage = storage

    # ------------------------------------------------------------------
    # Startup entry point
    # ------------------------------------------------------------------

    def ensure_master_key(self) -> bool:
        """
        Guarantee that crypto.master_key is set before the main UI is shown.

        First-run behaviour (no salt file on disk):
          - Ask the user to create a master password.
          - Generate a fresh random salt and write a key-check file.
          - Exit the process if the user cancels.

        Existing-installation behaviour (salt file found on disk):
          - Show a login dialog with four actions: Unlock, Restore from
            recovery file, Factory reset, or Exit.
          - Loop until one of those actions succeeds or the user exits.

        Returns True when the application may safely continue.
        Calls sys.exit() if the user explicitly chooses to quit or if the
        'cryptography' package is not installed.
        """
        if not self.crypto.available:
            messagebox.showerror(
                "Cryptography required",
                "This application requires the 'cryptography' package.\n"
                "Install it with:  pip install cryptography",
            )
            sys.exit(1)

        # Import Fernet here (safe because we just confirmed CRYPTO_AVAILABLE).
        from cryptography.fernet import Fernet

        salt = self.crypto.load_salt()

        if salt:
            # ---- Existing installation: require the correct password ----
            while True:
                action, pwd = self._prompt_master_password_with_options()

                if action == "exit":
                    if messagebox.askyesno("Exit", "Exit without unlocking?"):
                        try:
                            self.root.destroy()
                        except Exception:
                            pass
                        sys.exit(1)
                    # User clicked 'No' on the exit confirmation – loop back.
                    continue

                if action == "restored":
                    # Recovery flow already set crypto.master_key.
                    if self.crypto.master_key:
                        logger.info("Master password restored via recovery file")
                        return True
                    continue

                if action == "factory_reset":
                    logger.info("Factory reset performed from master-password dialog")
                    return True

                if action == "unlock":
                    if not pwd:
                        messagebox.showinfo(
                            "Required",
                            "You must enter the master password to use the application.",
                        )
                        continue
                    if self.crypto.verify_master_password(pwd):
                        self.crypto.master_key = self.crypto.derive_key(pwd, salt)
                        logger.info("Master password verified")
                        return True
                    messagebox.showwarning(
                        "Invalid",
                        "The master password is incorrect. Please try again.",
                    )
                    # Loop back to the dialog.

        else:
            # ---- First run: create a new master password ----
            pwd = self._prompt_create_master_password()
            if not pwd:
                messagebox.showerror(
                    "Required",
                    "A master password is required to use the application.",
                )
                sys.exit(1)

            new_salt = self.crypto.create_and_store_salt()
            self.crypto.master_key = self.crypto.derive_key(pwd, new_salt)
            try:
                self.crypto.create_keycheck_file(Fernet(self.crypto.master_key))
                logger.info("Created master password and key-check file")
                return True
            except Exception:
                logger.exception("Failed to create key-check file")
                messagebox.showerror("Error", "Failed to set up encryption.")
                sys.exit(1)

    # ------------------------------------------------------------------
    # Login dialog
    # ------------------------------------------------------------------

    def _prompt_master_password_with_options(self) -> Tuple[str, Optional[str]]:
        """
        Display a modal dialog with four buttons:
          - 'Unlock'                      – unlock with master password
          - 'Restore from recovery file'  – recover via a recovery file
          - 'Factory reset (wipe local data)' – erase all application data
          - 'Exit'                        – quit the application

        Returns a (action, password) tuple.
        *action* is one of: 'unlock', 'restored', 'factory_reset', 'exit'.
        *password* is set only for the 'unlock' action.
        """
        result: dict = {"action": None, "pwd": None}

        dlg = Toplevel(self.root)
        dlg.title("Master password")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        Label(dlg, text="Enter master password:").grid(
            row=0, column=0, columnspan=4, padx=12, pady=(12, 6)
        )

        pwd_var = StringVar()
        pwd_entry = Entry(dlg, textvariable=pwd_var, show="*", width=40)
        pwd_entry.grid(row=1, column=0, columnspan=4, padx=12, pady=(0, 12))
        pwd_entry.focus_set()

        def do_unlock():
            result["action"] = "unlock"
            result["pwd"] = pwd_var.get()
            dlg.destroy()

        def do_restore():
            # Attempt recovery; if it succeeds the dialog is closed.
            ok = self._prompt_restore_from_recovery_file()
            if ok:
                result["action"] = "restored"
                dlg.destroy()
            # On failure we stay in the dialog so the user can try again.

        def do_factory():
            # Attempt factory reset; if it succeeds the dialog is closed.
            ok = self.prompt_factory_reset()
            if ok:
                result["action"] = "factory_reset"
                dlg.destroy()

        def do_exit():
            result["action"] = "exit"
            dlg.destroy()

        ttk.Button(dlg, text="Unlock",
                   command=do_unlock).grid(row=2, column=0, padx=6, pady=(0, 12), sticky="we")
        ttk.Button(dlg, text="Restore from recovery file",
                   command=do_restore).grid(row=2, column=1, padx=6, pady=(0, 12), sticky="we")
        ttk.Button(dlg, text="Factory reset (wipe local data)",
                   command=do_factory).grid(row=2, column=2, padx=6, pady=(0, 12), sticky="we")
        ttk.Button(dlg, text="Exit",
                   command=do_exit).grid(row=2, column=3, padx=6, pady=(0, 12), sticky="we")

        # Allow pressing Enter in the password field to trigger Unlock.
        pwd_entry.bind("<Return>",    lambda _: do_unlock())
        pwd_entry.bind("<KP_Enter>",  lambda _: do_unlock())

        # Treat window-close (X button) as "Exit".
        dlg.protocol("WM_DELETE_WINDOW", do_exit)
        dlg.wait_window()

        return result["action"], result["pwd"]

    # ------------------------------------------------------------------
    # Password prompts (shared by first-run, recovery, and change flows)
    # ------------------------------------------------------------------

    def _prompt_create_master_password(self) -> Optional[str]:
        """
        Ask the user to choose a new master password and confirm it.

        Loops until both entries match or the user cancels.
        Returns the password string, or None if the user cancels.
        """
        while True:
            pwd = simpledialog.askstring(
                "Create master password",
                "Create a master password to encrypt your stored files:",
                show="*",
            )
            if pwd is None:
                return None
            if pwd == "":
                messagebox.showwarning("Empty", "Master password cannot be empty.")
                continue
            confirm = simpledialog.askstring(
                "Confirm master password",
                "Confirm master password:",
                show="*",
            )
            if confirm is None:
                return None
            if confirm == pwd:
                return pwd
            messagebox.showwarning("Mismatch", "Passwords did not match. Please try again.")

    def _prompt_new_master_password_required(self) -> Optional[str]:
        """
        Like _prompt_create_master_password() but with slightly different
        dialog titles used in the password-change and recovery-reset flows
        where a *new* password is explicitly required.

        Returns the new password string, or None if the user cancels.
        """
        while True:
            pwd = simpledialog.askstring(
                "New master password",
                "Enter a new master password:",
                show="*",
            )
            if pwd is None:
                return None
            if pwd == "":
                messagebox.showwarning("Empty", "Master password cannot be empty.")
                continue
            confirm = simpledialog.askstring(
                "Confirm new master password",
                "Confirm new master password:",
                show="*",
            )
            if confirm is None:
                return None
            if confirm != pwd:
                messagebox.showwarning("Mismatch", "Passwords did not match. Please try again.")
                continue
            return pwd

    # ------------------------------------------------------------------
    # Recovery file – restore flow
    # ------------------------------------------------------------------

    def _prompt_restore_from_recovery_file(self) -> bool:
        """
        Ask the user to select a recovery file and enter the recovery
        passphrase, then execute the full restoration flow.

        Returns True if the master password was successfully reset;
        False otherwise.
        """
        if not self.crypto.available:
            messagebox.showwarning(
                "Unavailable",
                "Recovery functionality requires the 'cryptography' package.",
            )
            return False

        path = filedialog.askopenfilename(
            title="Select recovery file",
            filetypes=[
                ("Recovery file", "*.recovery.json"),
                ("JSON",          "*.json"),
                ("All files",     "*.*"),
            ],
        )
        if not path:
            return False

        passphrase = simpledialog.askstring(
            "Recovery passphrase",
            "Enter the recovery passphrase:",
            show="*",
        )
        if passphrase is None:
            return False

        return self._restore_master_from_recovery_file(path, passphrase)

    def _restore_master_from_recovery_file(
        self, recovery_file_path: str, recovery_passphrase: str
    ) -> bool:
        """
        Full master-password reset via a recovery file.

        Steps:
          1. Load the old master key from the recovery file using the
             recovery passphrase.
          2. Verify the recovered key against the key-check file (or, if
             that is missing, against any existing encrypted data file).
          3. Prompt the user for a new master password.
          4. Re-encrypt all data files from old key to new key (atomic).
          5. Persist the new salt and key-check file.
          6. Update the runtime master key in CryptoManager.

        Returns True on success; False on any failure (with a dialog shown
        to the user explaining what went wrong).
        """
        from cryptography.fernet import Fernet

        # Step 1 – retrieve old master key from recovery file.
        old_master_key = self.crypto.restore_from_recovery_file(
            recovery_file_path, recovery_passphrase
        )
        if old_master_key is None:
            messagebox.showerror(
                "Recovery failed",
                "Could not decrypt the recovery file.\n"
                "Check that you selected the correct file and entered the correct passphrase.",
            )
            return False

        # Step 2 – verify the recovered key actually matches the stored data.
        verified = False
        cfg = self.config

        # Preferred: try the key-check file.
        if os.path.exists(cfg.keycheck_path):
            try:
                with open(cfg.keycheck_path, "rb") as fh:
                    Fernet(old_master_key).decrypt(fh.read())
                verified = True
            except Exception:
                verified = False

        # Fallback: try decrypting any encrypted data file.
        if not verified:
            for enc_path in [cfg.data_txt_enc, cfg.data_xlsx_enc, cfg.data_csv_enc]:
                if os.path.exists(enc_path):
                    try:
                        with open(enc_path, "rb") as fh:
                            Fernet(old_master_key).decrypt(fh.read())
                        verified = True
                        break
                    except Exception:
                        pass

        if not verified:
            messagebox.showerror(
                "Verification failed",
                "The recovery file key does not match the current encrypted data.\n"
                "Aborting reset.",
            )
            logger.error("Recovery file key did not verify against keycheck or encrypted files")
            return False

        # Step 3 – ask for a new master password.
        new_pwd = self._prompt_new_master_password_required()
        if new_pwd is None:
            messagebox.showinfo("Cancelled", "Password reset cancelled.")
            return False

        # Step 4 – derive new key and atomically re-encrypt all data files.
        tentative_salt = os.urandom(16)
        new_master_key = self.crypto.derive_key(new_pwd, tentative_salt)

        if not self.crypto.rewrap_encrypted_files(old_master_key, new_master_key):
            messagebox.showerror(
                "Error",
                "Failed to re-encrypt files during password reset.\n"
                "No changes were applied.",
            )
            return False

        # Step 5 – persist new salt and key-check (back up old files first).
        salt_bak: Optional[str] = None
        keycheck_bak: Optional[str] = None
        try:
            if os.path.exists(cfg.salt_path):
                salt_bak = cfg.salt_path + ".bak"
                shutil.copy2(cfg.salt_path, salt_bak)
            if os.path.exists(cfg.keycheck_path):
                keycheck_bak = cfg.keycheck_path + ".bak"
                shutil.copy2(cfg.keycheck_path, keycheck_bak)

            with open(cfg.salt_path, "wb") as sf:
                sf.write(tentative_salt)
            self.crypto.create_keycheck_file(Fernet(new_master_key))

            # Step 6 – update runtime state.
            self.crypto.master_key    = new_master_key
            self.crypto.use_encryption = True
            logger.info("Master password reset via recovery file")

            bak_note = ""
            if salt_bak or keycheck_bak:
                bak_note = "\nBackups of original salt/keycheck files have been kept with a .bak suffix."
            messagebox.showinfo(
                "Reset complete",
                f"Master password reset and all files re-encrypted successfully.{bak_note}",
            )

            # Offer to create a new recovery file immediately (the old one is now outdated).
            if messagebox.askyesno(
                "Create new recovery file",
                "Your old recovery file is now outdated.\nCreate a new one now?",
            ):
                self.prompt_create_recovery_file()

            return True

        except Exception:
            logger.exception("Failed to persist new salt/keycheck after recovery reset")
            # Best-effort: try to restore salt/keycheck from backups.
            for orig, bak in [(cfg.salt_path, salt_bak), (cfg.keycheck_path, keycheck_bak)]:
                if bak and os.path.exists(bak):
                    try:
                        shutil.copy2(bak, orig)
                    except Exception:
                        logger.exception("Failed to restore %s from backup", orig)
            messagebox.showerror(
                "Error",
                "Reset succeeded but the new credentials could not be persisted.\n"
                "Manual intervention may be required.",
            )
            return False

    # ------------------------------------------------------------------
    # Recovery file – creation flow (called from the Settings panel)
    # ------------------------------------------------------------------

    def prompt_create_recovery_file(self) -> None:
        """
        Ask the user for a recovery passphrase and a save location, then
        create a recovery file that can later be used to reset the master
        password.

        The recovery file is a JSON document that contains the master key
        encrypted with a key derived from the recovery passphrase.  The
        user should store it safely offline (e.g. on a USB drive or in a
        secure location separate from the computer).
        """
        if not self.crypto.available:
            messagebox.showwarning(
                "Unavailable",
                "Recovery functionality requires the 'cryptography' package.",
            )
            return
        if not self.crypto.master_key:
            messagebox.showwarning(
                "No master key",
                "Create or unlock a master password before creating a recovery file.",
            )
            return

        # Prompt for the recovery passphrase (with confirmation loop).
        while True:
            p1 = simpledialog.askstring(
                "Recovery passphrase",
                "Enter a recovery passphrase (store this offline – if lost it cannot be recovered):",
                show="*",
            )
            if p1 is None:
                return
            if p1 == "":
                messagebox.showwarning("Empty", "Recovery passphrase cannot be empty.")
                continue
            p2 = simpledialog.askstring(
                "Confirm recovery passphrase",
                "Confirm recovery passphrase:",
                show="*",
            )
            if p2 is None:
                return
            if p1 != p2:
                messagebox.showwarning("Mismatch", "Passphrases did not match. Please try again.")
                continue

            # Ask where to save the file.
            save_to = filedialog.asksaveasfilename(
                title="Save recovery file",
                defaultextension=".recovery.json",
                filetypes=[
                    ("Recovery file", "*.recovery.json"),
                    ("JSON",          "*.json"),
                    ("All files",     "*.*"),
                ],
            )
            if not save_to:
                return

            ok = self.crypto.create_recovery_file(save_to, p1)
            if ok:
                messagebox.showinfo(
                    "Recovery file created",
                    f"Recovery file saved to:\n{save_to}\n\nStore it safely offline.",
                )
            else:
                messagebox.showerror(
                    "Failed",
                    "Could not create the recovery file. See the application log for details.",
                )
            return

    # ------------------------------------------------------------------
    # Change master password (called from the Settings panel)
    # ------------------------------------------------------------------

    def prompt_change_master_password(self) -> None:
        """
        Interactively change the master password.

        Flow:
          1. Verify the current master password.
          2. Ask for a new master password (with confirmation).
          3. Derive a new key with a fresh random salt.
          4. Atomically re-encrypt all data files from old to new key.
          5. Persist the new salt and key-check file.
          6. Update the runtime master key.
        """
        from cryptography.fernet import Fernet

        if not self.crypto.available:
            messagebox.showwarning(
                "Unavailable",
                "Encryption requires the 'cryptography' package.",
            )
            return
        if not self.crypto.master_key:
            messagebox.showwarning("No master key", "No master password is currently set.")
            return

        # Step 1 – verify current password.
        current_pwd = simpledialog.askstring(
            "Current master password",
            "Enter your current master password:",
            show="*",
        )
        if current_pwd is None:
            return
        if not self.crypto.verify_master_password(current_pwd):
            messagebox.showerror("Incorrect", "The current master password is incorrect.")
            return

        # Step 2 – ask for new password.
        new_pwd = self._prompt_new_master_password_required()
        if new_pwd is None:
            messagebox.showinfo("Cancelled", "Password change cancelled.")
            return

        # Step 3 – derive new key with a fresh salt.
        try:
            new_salt       = os.urandom(16)
            new_master_key = self.crypto.derive_key(new_pwd, new_salt)
        except Exception:
            logger.exception("Failed to derive new master key")
            messagebox.showerror("Error", "Failed to create the new master key.")
            return

        # Step 4 – re-encrypt all data files atomically.
        if not self.crypto.rewrap_encrypted_files(self.crypto.master_key, new_master_key):
            messagebox.showerror(
                "Error",
                "Failed to re-encrypt the data files.\nNo changes were applied.",
            )
            return

        # Step 5 – persist new salt and key-check file.
        try:
            with open(self.config.salt_path, "wb") as sf:
                sf.write(new_salt)
            self.crypto.create_keycheck_file(Fernet(new_master_key))

            # Step 6 – update the runtime master key.
            self.crypto.master_key = new_master_key
            logger.info("Master password changed successfully")
            messagebox.showinfo("Done", "Master password changed successfully.")

        except Exception:
            logger.exception("Failed to write new salt/keycheck after password change")
            messagebox.showerror(
                "Error",
                "Failed to persist the new credentials.\n"
                "Original files were restored where possible.",
            )

    # ------------------------------------------------------------------
    # Factory reset
    # ------------------------------------------------------------------

    def prompt_factory_reset(self) -> bool:
        """
        Strongly confirm with the user before performing a factory reset,
        then call _factory_reset() if confirmed.

        The user must:
          1. Click 'Yes' on an initial warning dialog.
          2. Type the word DELETE in a text prompt.
          3. Click 'Yes' on a final confirmation.

        Returns True if the factory reset was executed successfully.
        """
        if not messagebox.askyesno(
            "Factory reset — WARNING",
            "This will permanently remove in-app access to all current\n"
            "encrypted data. Continue?",
        ):
            return False

        warning = (
            "Factory reset will permanently remove in-app access to all current\n"
            "encrypted data.\n\n"
            "All related files (encrypted data, salt, keycheck, config) will be\n"
            "moved to a timestamped backup folder inside the application data directory.\n\n"
            "If you have a recovery file, cancel here and use 'Restore from recovery\n"
            "file' instead.\n\n"
            "Type  DELETE  to confirm and proceed."
        )
        confirm = simpledialog.askstring(
            "Confirm factory reset",
            warning,
            parent=self.root,
        )
        if confirm is None or confirm.strip() != "DELETE":
            messagebox.showinfo("Cancelled", "Factory reset cancelled.")
            return False

        if not messagebox.askyesno(
            "Final confirmation",
            "Are you absolutely sure?\nThis will move your data to a backup folder\n"
            "and disable encryption.",
        ):
            return False

        ok = self._factory_reset()
        if ok:
            messagebox.showinfo(
                "Factory reset complete",
                "All data moved to backup and encryption disabled.\n"
                "You may now create a new master password on next use.",
            )
        else:
            messagebox.showerror(
                "Factory reset failed",
                "Could not complete factory reset. See the log for details.",
            )
        return ok

    def _factory_reset(self) -> bool:
        """
        Move (or copy-then-truncate) all application data files to a
        timestamped backup folder, then clear the in-memory master key and
        disable encryption in the config.

        Strategy per file (tried in order):
          1. Atomic rename (os.replace) – fastest; moves file in one step.
          2. Copy (shutil.copy2) then delete original – used when rename
             fails (e.g. cross-device move on some file systems).
          3. Truncate original to zero bytes – last resort if deletion fails
             (data is wiped even if the inode remains).

        If any file cannot be handled by at least step 3, the whole reset
        is rolled back (moved files are moved back, copied backups removed)
        and False is returned.

        Note: the application log file is intentionally excluded because the
        rotating log handler keeps it open on Windows, and moving it would
        cause errors.

        Returns True on complete success.
        """
        try:
            ts          = time.strftime("%Y%m%d-%H%M%S")
            backup_root = os.path.join(self.config.user_data_dir, "factory_reset_backups")
            os.makedirs(backup_root, exist_ok=True)
            backup_dir  = os.path.join(backup_root, ts)
            os.makedirs(backup_dir, exist_ok=True)

            cfg = self.config
            # All files to be moved/removed.
            # LOG_PATH is intentionally excluded (open file handle on Windows).
            candidates = [
                cfg.data_txt_enc, cfg.data_xlsx_enc, cfg.data_csv_enc,
                cfg.data_txt,     cfg.data_xlsx,     cfg.data_csv,
                cfg.salt_path,    cfg.keycheck_path, cfg.config_path,
            ]

            moved:  list = []  # (orig, dest) – successfully renamed
            copied: list = []  # (orig, dest) – copied, orig still present
            failed: list = []  # original paths that could not be handled

            for p in candidates:
                if not os.path.exists(p):
                    continue
                dest = os.path.join(backup_dir, os.path.basename(p))

                # --- Attempt 1: atomic rename ---
                try:
                    os.replace(p, dest)
                    moved.append((p, dest))
                    continue
                except Exception as ex:
                    logger.debug("os.replace failed for %s: %s", p, ex)

                # --- Attempt 2: copy then delete ---
                try:
                    shutil.copy2(p, dest)
                    copied.append((p, dest))
                    try:
                        os.remove(p)
                        continue
                    except Exception as ex_rm:
                        logger.debug("os.remove failed for %s: %s", p, ex_rm)
                        # --- Attempt 3: truncate ---
                        try:
                            with open(p, "r+b") as fh:
                                fh.truncate(0)
                            continue
                        except Exception as ex_tr:
                            logger.debug("truncate failed for %s: %s", p, ex_tr)
                            failed.append(p)
                            continue
                except Exception as ex_copy:
                    logger.exception("Failed to copy %s to backup: %s", p, ex_copy)
                    failed.append(p)

            if failed:
                # Roll back: restore renamed files and remove orphan backups.
                for orig, dest in moved:
                    try:
                        shutil.move(dest, orig)
                    except Exception:
                        logger.exception("Failed to restore %s from backup", dest)
                for _, dest in copied:
                    try:
                        if os.path.exists(dest):
                            os.remove(dest)
                    except Exception:
                        pass

                names = ", ".join(os.path.basename(p) for p in failed)
                messagebox.showerror(
                    "Reset failed",
                    f"Could not move/backup these files: {names}\n"
                    "Aborting factory reset. See log for details.",
                )
                logger.error("Factory reset aborted; failed to backup: %s", failed)
                return False

            # All candidate files are gone.  Clear runtime state and config.
            self.crypto.master_key    = None
            self.crypto.use_encryption = False
            self.config.set("use_encryption", False)
            self.config.save()
            self.crypto.cleanup_temp_files()

            logger.info("Factory reset performed; backups stored in %s", backup_dir)
            return True

        except Exception as exc:
            logger.exception("Factory reset failed unexpectedly")
            messagebox.showerror(
                "Reset failed",
                f"An unexpected error occurred:\n{exc}\nSee log for details.",
            )
            return False
