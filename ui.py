"""
ui.py – Main application window.

This module contains AppWindow, which is the top-level class that owns
the Tkinter root window and wires all subsystems together.

Responsibilities:
  - Create AppConfig, CryptoManager, DataStorage and AuthManager in the
    correct dependency order.
  - Create the Tk root window and apply visual styling.
  - Delegate the master-password prompt to AuthManager before the UI loads.
  - Build the complete widget hierarchy (header, form, action buttons,
    settings panel) with a scrollable canvas that adapts to the window size.
  - Implement all event handlers (save, generate password, open files, …).

Widget hierarchy
----------------
root (Tk)
 └─ outer (Frame)
     ├─ _canvas (Canvas)           ← scrollable content area
     │   └─ content_frame (Frame)
     │       ├─ row 0: header_frame  (logo · title · update button)
     │       ├─ row 1: ttk.Separator
     │       ├─ row 2: Website   label + entry
     │       ├─ row 3: Email     label + entry
     │       ├─ row 4: Password  label + entry + [Show | Generate]
     │       ├─ row 5: _action_frame  [Save entry | Open text | Open Excel]
     │       └─ row 6: options_frame  (settings + management buttons)
     ├─ _v_scroll (Scrollbar, vertical)
     └─ _h_scroll (Scrollbar, horizontal)
"""

import atexit
import logging
import webbrowser
from random import choice, shuffle
from tkinter import (
    Canvas, Checkbutton, Entry, Frame, IntVar, PhotoImage,
    Spinbox, Tk, messagebox, ttk,
)
from typing import Optional

# Local application modules.
from config import AppConfig, APP_VERSION, MIN_CONTENT_WIDTH, ENTRY_MIN_CHARS, SYMBOLS, MIN_LENGTH
from crypto import CryptoManager
from storage import DataStorage, EntryValidationError
from auth import AuthManager

logger = logging.getLogger("PasswordManager")

# ---------------------------------------------------------------------------
# Visual constants (fonts, colours, spacing)
# ---------------------------------------------------------------------------
APP_FONT    = ("Segoe UI", 10)
HEADER_FONT = ("Segoe UI", 13, "bold")
SMALL_FONT  = ("Segoe UI", 9)
BUTTON_FONT = ("Segoe UI", 10)

BG           = "#f0f2f5"   # main window / frame background
ENTRY_BG     = "#ffffff"   # entry field background (white)
ACCENT       = "#1a6fb5"   # primary accent colour (blue – Save button)
ACCENT_HOVER = "#154f85"   # darker shade shown on hover / press


class AppWindow:
    """
    The main application window and entry point for all UI logic.

    Instantiation:
      1. Creates all subsystem objects (AppConfig → CryptoManager →
         DataStorage → AuthManager).
      2. Creates the Tk root window and applies visual styling.
      3. Calls AuthManager.ensure_master_key() so the user must authenticate
         before any UI is displayed.
      4. Builds the complete widget hierarchy.

    Call run() to enter the Tkinter event loop.
    """

    def __init__(self) -> None:
        # ----------------------------------------------------------------
        # 1. Create subsystems in dependency order.
        # ----------------------------------------------------------------
        self.config  = AppConfig()
        self.crypto  = CryptoManager(self.config)
        self.storage = DataStorage(self.config, self.crypto)

        # ----------------------------------------------------------------
        # 2. Create the Tk root window.
        #    The window must exist before AuthManager can open dialogs.
        # ----------------------------------------------------------------
        self.root = Tk()
        self.root.title("Password Manager")
        self.root.geometry("760x540")
        self.root.config(padx=6, pady=6)

        # Allow the single child frame to fill the whole window.
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)

        # Load the window icon (best-effort; missing icon is not fatal).
        try:
            icon_path = self.config.resource_path("padlock.png")
            self.root.iconphoto(False, PhotoImage(file=icon_path))
        except Exception:
            logger.debug("Icon load failed – skipping")

        # Apply the visual theme and custom ttk styles.
        self._setup_styles()

        # ----------------------------------------------------------------
        # 3. Authenticate before building the UI.
        # ----------------------------------------------------------------
        self.auth = AuthManager(self.root, self.config, self.crypto, self.storage)
        ok = self.auth.ensure_master_key()

        if not ok and self.crypto.load_salt() is not None:
            # The salt file exists (encrypted installation) but no key was
            # provided – refuse to continue.
            messagebox.showerror(
                "Locked",
                "The application cannot start without the master password.",
            )
            logger.error("Master password not provided; exiting.")
            try:
                self.root.destroy()
            except Exception:
                pass
            import sys; sys.exit(1)

        # ----------------------------------------------------------------
        # 4. Internal widget references assigned during UI construction.
        # ----------------------------------------------------------------
        self.website_entry:       Optional[Entry]       = None
        self.email_entry:         Optional[Entry]       = None
        self.password_entry:      Optional[Entry]       = None
        self.show_hide_btn:       Optional[ttk.Button]  = None
        self._password_visible:   bool                  = False
        self._auto_copy_var:      Optional[IntVar]      = None
        self._clipboard_sec_var:  Optional[IntVar]      = None

        # ----------------------------------------------------------------
        # 5. Build the complete UI.
        # ----------------------------------------------------------------
        self._build_scrollable_frame()
        self._build_header()
        self._build_form()
        self._build_action_buttons()
        self._build_options_frame()
        self._setup_keybindings()

        # Ensure scroll-bar visibility is correct once the window is drawn.
        self.root.after(50, self._update_scrollbars)

        # Register temp-file cleanup on normal process exit.
        atexit.register(self.crypto.cleanup_temp_files)

        # Handle the window close button.
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

    # ------------------------------------------------------------------
    # Visual theme and ttk styles
    # ------------------------------------------------------------------

    def _setup_styles(self) -> None:
        """
        Apply the 'clam' ttk theme and configure custom named styles.

        Styles defined:
          TFrame, TLabelframe, TLabelframe.Label – background colour.
          App.TLabel     – standard label font.
          Header.TLabel  – larger bold label used in the header.
          Small.TLabel   – smaller grey label (secondary information).
          App.TButton    – standard button with hover/press states.
          Primary.TButton – filled blue button (Save entry).
        """
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass  # Fall back to whatever theme is available.

        # Frame and label-frame backgrounds.
        style.configure("TFrame",            background=BG)
        style.configure("TLabelframe",       background=BG)
        style.configure("TLabelframe.Label", background=BG,
                        font=("Segoe UI", 9, "bold"), foreground="#555555")

        # Label styles.
        style.configure("App.TLabel",    font=APP_FONT,    background=BG, foreground="#222222")
        style.configure("Header.TLabel", font=HEADER_FONT, background=BG, foreground="#1a2540")
        style.configure("Small.TLabel",  font=SMALL_FONT,  background=BG, foreground="#666666")

        # Standard button with hover/press colour map.
        style.configure("App.TButton", font=BUTTON_FONT, padding=(8, 5))
        try:
            style.map(
                "App.TButton",
                background=[("pressed", "#c5cfe0"), ("active", "#dce6f5"), ("!active", "#e2e8f0")],
                foreground=[("pressed", "#111"),    ("active", "#003a80")],
            )
        except Exception:
            pass

        # Primary (Save) button – filled accent-blue background.
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(8, 6))
        try:
            style.map(
                "Primary.TButton",
                background=[
                    ("pressed", ACCENT_HOVER),
                    ("active",  ACCENT_HOVER),
                    ("!active", ACCENT),
                ],
                foreground=[
                    ("pressed", "white"),
                    ("active",  "white"),
                    ("!active", "white"),
                ],
            )
        except Exception:
            pass

        self.root.configure(bg=BG)
        self.root.resizable(True, True)
        self.root.minsize(680, 460)

    # ------------------------------------------------------------------
    # Scrollable content frame
    # ------------------------------------------------------------------

    def _build_scrollable_frame(self) -> None:
        """
        Create the outer Frame → Canvas + scrollbars → inner content Frame.

        The canvas acts as a viewport.  The content_frame lives inside the
        canvas and holds all actual widgets.  Scroll-bars appear only when
        the content is larger than the canvas:
          - Horizontal: when window width < MIN_CONTENT_WIDTH.
          - Vertical:   when the content height exceeds the window height.
        """
        outer = Frame(self.root)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)

        # Create the canvas and both scroll-bars.
        self._canvas   = Canvas(outer, highlightthickness=0, bg=BG)
        self._v_scroll = ttk.Scrollbar(outer, orient="vertical",   command=self._canvas.yview)
        self._h_scroll = ttk.Scrollbar(outer, orient="horizontal", command=self._canvas.xview)
        self._canvas.configure(
            xscrollcommand=self._h_scroll.set,
            yscrollcommand=self._v_scroll.set,
        )

        self._canvas.grid(row=0, column=0, sticky="nsew")
        self._v_scroll.grid(row=0, column=1, sticky="ns")
        self._h_scroll.grid(row=1, column=0, sticky="we")

        # The inner frame holds all UI widgets; it lives inside the canvas.
        self.content_frame = Frame(self._canvas, bg=BG)
        self._canvas_window = self._canvas.create_window(
            (0, 0), window=self.content_frame, anchor="nw"
        )

        # 3-column grid layout inside content_frame:
        #   col 0 – labels         (fixed width ~130 px)
        #   col 1 – entries        (expands with window width)
        #   col 2 – per-row buttons (fixed width ~240 px)
        self.content_frame.columnconfigure(0, weight=0, minsize=130)
        self.content_frame.columnconfigure(1, weight=1)
        self.content_frame.columnconfigure(2, weight=0, minsize=240)

        # Bind resize events to keep the canvas in sync.
        self.content_frame.bind("<Configure>", self._on_content_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        # Bind mouse-wheel scrolling (cross-platform).
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)  # Windows / macOS
        self._canvas.bind_all("<Button-4>",   self._on_mousewheel)  # Linux scroll-up
        self._canvas.bind_all("<Button-5>",   self._on_mousewheel)  # Linux scroll-down

    # ------------------------------------------------------------------
    # Header row (row 0)
    # ------------------------------------------------------------------

    def _build_header(self) -> None:
        """
        Build the header row:
          - Application logo (PNG, scaled to ≤34 px) on the left side of
            the centre block.
          - 'Password Manager' title + subtitle centred.
          - 'About' button and 'Check for updates' button pinned to the
            far right (in that order).
          - A horizontal separator below the header.

        All elements are placed inside a ttk.Frame using a 6-column grid
        with left/right spacer columns (weight=1) that push the logo+title
        block to the centre.
        """
        try:
            hf = ttk.Frame(self.content_frame, padding=(6, 8, 6, 6))
            hf.grid(row=0, column=0, columnspan=3, sticky="we")

            # left spacer | logo | title+subtitle | right spacer | about | update btn
            hf.columnconfigure(0, weight=1)  # left spacer
            hf.columnconfigure(1, weight=0)  # logo
            hf.columnconfigure(2, weight=0)  # title / subtitle
            hf.columnconfigure(3, weight=1)  # right spacer
            hf.columnconfigure(4, weight=0)  # about button
            hf.columnconfigure(5, weight=0)  # update button

            # Logo (column 1) – load PNG or fall back to text placeholder.
            try:
                img = PhotoImage(file=self.config.resource_path("padlock.png"))
                # Scale down if larger than 34 × 34 px to keep the header compact.
                w, h = img.width(), img.height()
                if w > 34 or h > 34:
                    factor = max(1, int(max(w, h) / 34))
                    img = img.subsample(factor, factor)
                logo_lbl = ttk.Label(hf, image=img, background=BG)
                logo_lbl.image = img  # hold a reference to prevent garbage collection
                logo_lbl.grid(row=0, column=1, rowspan=2, padx=(0, 8), sticky="e")
            except Exception:
                # Logo file is missing – use a simple text placeholder.
                ttk.Label(hf, text="[PM]", style="Header.TLabel").grid(
                    row=0, column=1, rowspan=2, padx=(0, 8), sticky="e"
                )

            # Title and subtitle (column 2).
            ttk.Label(hf, text="Password Manager",    style="Header.TLabel").grid(
                row=0, column=2, sticky="w"
            )
            ttk.Label(hf, text="Secure · Encrypted · Simple", style="Small.TLabel").grid(
                row=1, column=2, sticky="w"
            )

            # About button (column 4).
            ttk.Button(
                hf, text="About",
                style="App.TButton", command=self._show_about,
            ).grid(row=0, column=4, rowspan=2, padx=(0, 6), sticky="e")

            # Check-for-updates button (column 5).
            ttk.Button(
                hf, text="Check for updates",
                style="App.TButton", command=self._check_for_updates,
            ).grid(row=0, column=5, rowspan=2, sticky="e")

            # Horizontal separator below the header (row 1 of content_frame).
            ttk.Separator(self.content_frame, orient="horizontal").grid(
                row=1, column=0, columnspan=3, sticky="we", pady=(0, 6)
            )

        except Exception:
            logger.exception("Failed to build header")

    # ------------------------------------------------------------------
    # Main form – Website / Email / Password (rows 2–4)
    # ------------------------------------------------------------------

    def _build_form(self) -> None:
        """
        Build the three input rows:
          Row 2 – Website label + entry (spans columns 1–2)
          Row 3 – Email / Username label + entry (spans columns 1–2)
          Row 4 – Password label + masked entry + [Show/Hide | Generate]

        Constants used for padding:
          lx  = (left-pad, right-pad) for label cells
          ex  = (left-pad, right-pad) for entry / right-column cells
          rpy = vertical padding per row
        """
        cf  = self.content_frame
        lx  = (14, 8)   # label column: left-pad=14, right-pad=8
        ex  = (0, 14)   # entry / right-column: right-pad=14
        rpy = (6, 6)    # symmetric vertical padding

        # --- Row 2: Website ---
        ttk.Label(cf, text="Website:", style="App.TLabel").grid(
            row=2, column=0, padx=lx, pady=rpy, sticky="w"
        )
        self.website_entry = Entry(
            cf, width=ENTRY_MIN_CHARS,
            relief="solid", bd=1, bg=ENTRY_BG, font=APP_FONT,
        )
        # Entry spans columns 1 and 2 so it fills the full width.
        self.website_entry.grid(row=2, column=1, columnspan=2, padx=ex, pady=rpy, sticky="we")

        # --- Row 3: Email / Username ---
        ttk.Label(cf, text="Email / Username:", style="App.TLabel").grid(
            row=3, column=0, padx=lx, pady=rpy, sticky="w"
        )
        self.email_entry = Entry(
            cf, width=ENTRY_MIN_CHARS,
            relief="solid", bd=1, bg=ENTRY_BG, font=APP_FONT,
        )
        self.email_entry.grid(row=3, column=1, columnspan=2, padx=ex, pady=rpy, sticky="we")

        # --- Row 4: Password ---
        ttk.Label(cf, text="Password:", style="App.TLabel").grid(
            row=4, column=0, padx=lx, pady=rpy, sticky="w"
        )
        self.password_entry = Entry(
            cf, width=ENTRY_MIN_CHARS, show="*",  # masked by default
            relief="solid", bd=1, bg=ENTRY_BG, font=APP_FONT,
        )
        # Entry occupies only column 1; the button sub-frame occupies column 2.
        self.password_entry.grid(row=4, column=1, padx=(0, 6), pady=rpy, sticky="we")

        # Show/Hide and Generate buttons sit in a shared sub-frame (column 2).
        pwd_btns = ttk.Frame(cf)
        pwd_btns.grid(row=4, column=2, padx=ex, pady=rpy, sticky="we")
        pwd_btns.columnconfigure(0, weight=1)
        pwd_btns.columnconfigure(1, weight=1)

        self.show_hide_btn = ttk.Button(
            pwd_btns, text="Show",
            style="App.TButton", command=self._toggle_password_visibility,
        )
        self.show_hide_btn.grid(row=0, column=0, padx=(0, 5), sticky="we")

        ttk.Button(
            pwd_btns, text="Generate",
            style="App.TButton", command=self._generate_password,
        ).grid(row=0, column=1, sticky="we")

        # Prevent any content rows from expanding vertically.
        for r in range(2, 9):
            cf.rowconfigure(r, weight=0)

    # ------------------------------------------------------------------
    # Action buttons row (row 5)
    # ------------------------------------------------------------------

    def _build_action_buttons(self) -> None:
        """
        Build row 5: three equally-spaced action buttons.

          Save entry   – validates and saves the current form values.
          Open text    – opens the text data file with the default editor.
          Open Excel   – opens the Excel data file with the default app.

        All three buttons expand equally in the available width by assigning
        weight=1 to each column of the inner frame.
        """
        af = ttk.Frame(self.content_frame)
        af.grid(row=5, column=0, columnspan=3, padx=14, pady=(4, 6), sticky="we")
        af.columnconfigure(0, weight=1)
        af.columnconfigure(1, weight=1)
        af.columnconfigure(2, weight=1)

        ttk.Button(
            af, text="Save entry",
            style="Primary.TButton", command=self._save,
        ).grid(row=0, column=0, padx=(0, 5), sticky="we")

        ttk.Button(
            af, text="Open text data",
            style="App.TButton", command=self._open_txt,
        ).grid(row=0, column=1, padx=5, sticky="we")

        ttk.Button(
            af, text="Open Excel data",
            style="App.TButton", command=self._open_excel,
        ).grid(row=0, column=2, padx=(5, 0), sticky="we")

    # ------------------------------------------------------------------
    # Settings / Options frame (row 6)
    # ------------------------------------------------------------------

    def _build_options_frame(self) -> None:
        """
        Build row 6: a labelled settings group with two sub-rows.

        Sub-row 0 (inline settings):
          - 'Auto-copy generated password' checkbox.
          - 'Clear clipboard after N seconds' label + spinbox.

        Sub-row 1 (management buttons):
          - Create recovery file.
          - Change master password.
          - Factory reset.

        Changes to the checkbox and spinbox are saved immediately by their
        respective callback methods.
        """
        of = ttk.LabelFrame(self.content_frame, text="Settings", padding=(12, 8))
        of.grid(row=6, column=0, columnspan=3, padx=14, pady=(4, 10), sticky="we")

        # Column layout inside the settings frame.
        of.columnconfigure(0, weight=0)   # checkbox
        of.columnconfigure(1, weight=0)   # "Clear clipboard after:" label
        of.columnconfigure(2, weight=0)   # spinbox
        of.columnconfigure(3, weight=0)   # "seconds" label
        of.columnconfigure(4, weight=1)   # right spacer (pushes controls left)

        # --- Auto-copy checkbox ---
        self._auto_copy_var = IntVar(
            value=1 if self.config.get("auto_copy_generated", True) else 0
        )
        Checkbutton(
            of,
            text="Auto-copy generated password",
            variable=self._auto_copy_var,
            command=self._on_auto_copy_toggle,
            bg=BG, activebackground=BG, highlightthickness=0, font=APP_FONT,
        ).grid(row=0, column=0, sticky="w", padx=(0, 20))

        # --- Clipboard-clear spinbox ---
        ttk.Label(of, text="Clear clipboard after:", style="App.TLabel").grid(
            row=0, column=1, padx=(0, 4), sticky="w"
        )
        self._clipboard_sec_var = IntVar(
            value=int(self.config.get("clipboard_clear_seconds", 20))
        )
        Spinbox(
            of, from_=0, to=600, width=5,
            textvariable=self._clipboard_sec_var,
            command=self._on_clipboard_seconds_change,
        ).grid(row=0, column=2, padx=(0, 4))
        ttk.Label(of, text="seconds  (0 = never)", style="Small.TLabel").grid(
            row=0, column=3, sticky="w"
        )
        # Also save when the user types directly into the spinbox.
        self._clipboard_sec_var.trace_add("write", self._on_clipboard_seconds_change)

        # --- Management buttons sub-row ---
        mgmt = ttk.Frame(of)
        mgmt.grid(row=1, column=0, columnspan=5, pady=(10, 2), sticky="we")
        mgmt.columnconfigure(0, weight=1)
        mgmt.columnconfigure(1, weight=1)
        mgmt.columnconfigure(2, weight=1)

        ttk.Button(
            mgmt, text="Create recovery file",
            style="App.TButton", command=self.auth.prompt_create_recovery_file,
        ).grid(row=0, column=0, padx=(0, 5), sticky="we")

        ttk.Button(
            mgmt, text="Change master password",
            style="App.TButton", command=self.auth.prompt_change_master_password,
        ).grid(row=0, column=1, padx=5, sticky="we")

        ttk.Button(
            mgmt, text="Factory reset",
            style="App.TButton", command=self.auth.prompt_factory_reset,
        ).grid(row=0, column=2, padx=(5, 0), sticky="we")

    # ------------------------------------------------------------------
    # Keyboard shortcuts
    # ------------------------------------------------------------------

    def _setup_keybindings(self) -> None:
        """
        Bind keyboard shortcuts to the form entries:
          Enter on the Website field   → move focus to Email.
          Enter on the Email field     → move focus to Password.
          Ctrl+Enter on Password field → trigger Save.

        Initial focus is set to the Website field.
        """
        self.website_entry.bind("<Return>",   lambda _: self.email_entry.focus_set())
        self.email_entry.bind("<Return>",     lambda _: self.password_entry.focus_set())
        self.password_entry.bind("<Control-Return>",   lambda _: self._save())
        self.password_entry.bind("<Control-KP_Enter>", lambda _: self._save())

        try:
            self.website_entry.focus_set()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Scroll-bar management callbacks
    # ------------------------------------------------------------------

    def _on_content_configure(self, event) -> None:
        """
        Called whenever content_frame changes size.
        Updates the canvas scroll region so scroll-bars reflect the new
        content dimensions.
        """
        try:
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
            self._update_scrollbars()
        except Exception:
            pass

    def _on_canvas_configure(self, event) -> None:
        """
        Called whenever the canvas is resized (e.g. user resizes the window).

        Keeps the inner frame width in sync with the canvas:
          - If the canvas is narrower than MIN_CONTENT_WIDTH, the inner
            frame is kept at MIN_CONTENT_WIDTH so the horizontal scroll-bar
            becomes usable.
          - Otherwise the inner frame expands to fill the canvas (or to its
            natural requested width if that is larger).
        """
        try:
            cw            = event.width
            content_req_w = self.content_frame.winfo_reqwidth() or 0

            if cw < MIN_CONTENT_WIDTH:
                desired = MIN_CONTENT_WIDTH
            else:
                desired = max(content_req_w, cw)

            self._canvas.itemconfig(self._canvas_window, width=desired)
            self._update_scrollbars()
        except Exception:
            pass

    def _update_scrollbars(self) -> None:
        """
        Show or hide each scroll-bar depending on whether the content
        overflows the canvas in that direction.

        A 2-pixel tolerance is used to avoid flickering caused by rounding
        differences in geometry calculations.
        """
        try:
            cw = self._canvas.winfo_width()  or 0
            ch = self._canvas.winfo_height() or 0
            fw = self.content_frame.winfo_reqwidth()  or 0
            fh = self.content_frame.winfo_reqheight() or 0

            # Vertical scroll-bar: show when content is taller than canvas.
            if fh > ch + 2:
                self._v_scroll.grid(row=0, column=1, sticky="ns")
            else:
                self._v_scroll.grid_remove()

            # Horizontal scroll-bar: show when content is wider than canvas.
            if fw > cw + 2:
                self._h_scroll.grid(row=1, column=0, sticky="we")
            else:
                self._h_scroll.grid_remove()

            # Always keep the scroll region up to date.
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        except Exception:
            pass

    def _on_mousewheel(self, event) -> None:
        """
        Handle mouse-wheel events for vertical canvas scrolling.

        Linux generates Button-4 (scroll up) and Button-5 (scroll down)
        events; Windows and macOS use the event.delta value (multiples of
        ±120 per notch).
        """
        try:
            if hasattr(event, "num"):
                # Linux Button-4 / Button-5 events.
                if event.num == 4:
                    self._canvas.yview_scroll(-1, "units")
                elif event.num == 5:
                    self._canvas.yview_scroll(1, "units")
            else:
                # Windows / macOS: event.delta is positive = scroll up.
                delta = int(-1 * (event.delta / 120))
                if delta == 0:
                    delta = -1 if event.delta > 0 else 1
                self._canvas.yview_scroll(delta, "units")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _save(self) -> None:
        """
        Read the current form values and ask DataStorage to save the entry.

        On success:   show confirmation, clear all fields, refocus Website.
        On validation failure (EntryValidationError):
                      show a warning dialog and focus the offending field.
        On unexpected error:
                      show an error dialog.
        """
        website  = self.website_entry.get().strip()
        email    = self.email_entry.get().strip()
        password = self.password_entry.get().strip()

        try:
            self.storage.save_entry(website, email, password)
            messagebox.showinfo("Saved", "Entry saved successfully.")

            # Clear all form fields and move focus back to the start.
            self.website_entry.delete(0, "end")
            self.email_entry.delete(0, "end")
            self.password_entry.delete(0, "end")
            self.website_entry.focus_set()

        except EntryValidationError as exc:
            # A specific field failed – tell the user and focus that field.
            messagebox.showwarning("Input error", str(exc))
            field_map = {
                "website":  self.website_entry,
                "email":    self.email_entry,
                "password": self.password_entry,
            }
            widget = field_map.get(exc.field)
            if widget:
                widget.focus_set()

        except Exception:
            logger.exception("Unexpected error while saving entry")
            messagebox.showerror("Error", "An unexpected error occurred while saving.")

    def _toggle_password_visibility(self) -> None:
        """
        Toggle the password entry between masked ('*') and visible plain text.

        Updates the Show/Hide button label to reflect the current state.
        """
        self._password_visible = not self._password_visible
        if self._password_visible:
            self.password_entry.config(show="")
            self.show_hide_btn.config(text="Hide")
        else:
            self.password_entry.config(show="*")
            self.show_hide_btn.config(text="Show")

    def _generate_password(self) -> None:
        """
        Generate a random password and insert it into the password field.

        The password is composed of uppercase letters, lowercase letters,
        digits, and special characters (from the SYMBOLS constant in config).
        Its length is controlled by MIN_LENGTH.

        If the 'auto-copy generated password' option is enabled, the
        generated password is also copied to the system clipboard via
        pyperclip (optional library – failure is silently ignored).
        """
        try:
            pool = list(
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789"
            ) + list(SYMBOLS)
            shuffle(pool)
            pwd = "".join(choice(pool) for _ in range(MIN_LENGTH))

            self.password_entry.delete(0, "end")
            self.password_entry.insert(0, pwd)

            if self.config.get("auto_copy_generated", True):
                try:
                    import pyperclip
                    pyperclip.copy(pwd)
                except Exception:
                    pass  # pyperclip is optional; clipboard copy is best-effort.

        except Exception:
            logger.exception("Failed to generate password")
            messagebox.showerror("Error", "Could not generate a password.")

    def _open_txt(self) -> None:
        """
        Open the text data file and then restore focus to the Website entry.

        Focus is restored in a finally block to ensure it happens even if
        the file-open operation raises an exception.
        """
        try:
            self.storage.open_txt()
        finally:
            try:
                self.website_entry.focus_set()
            except Exception:
                pass

    def _open_excel(self) -> None:
        """
        Open the Excel data file and then restore focus to the Website entry.
        """
        try:
            self.storage.open_excel()
        finally:
            try:
                self.website_entry.focus_set()
            except Exception:
                pass

    def _on_auto_copy_toggle(self) -> None:
        """
        Persist the 'auto-copy generated password' preference immediately
        when the user toggles the checkbox.
        """
        self.config.set("auto_copy_generated", bool(self._auto_copy_var.get()))
        self.config.save()

    def _on_clipboard_seconds_change(self, *_) -> None:
        """
        Validate and persist the clipboard-clear timeout when the spinbox
        value changes (either via arrow keys or direct typing).

        Negative values are clamped to 0; non-integer input is reset to 20.
        """
        try:
            val = int(self._clipboard_sec_var.get())
            if val < 0:
                val = 0
                self._clipboard_sec_var.set(val)
        except Exception:
            val = 20
            self._clipboard_sec_var.set(val)
        self.config.set("clipboard_clear_seconds", val)
        self.config.save()

    def _show_about(self) -> None:
        """
        Display a modal 'About' dialog with information about the application:
        name, version, description, author, GitHub link and Python version.

        The GitHub link is rendered as a clickable blue label that opens the
        project page in the default web browser when clicked.
        """
        import sys as _sys
        from tkinter import Toplevel, Label, Frame, font as tkfont

        REPO_URL = "https://github.com/BurcutDragos/Simple-Password-Manager-Application"

        dlg = Toplevel(self.root)
        dlg.title("About Password Manager")
        dlg.resizable(False, False)
        dlg.configure(bg=BG)
        dlg.transient(self.root)
        dlg.grab_set()

        # ---- Logo ----
        try:
            img = PhotoImage(file=self.config.resource_path("padlock.png"))
            # Scale to roughly 48 × 48 px for the About dialog.
            w, h = img.width(), img.height()
            if w > 48 or h > 48:
                factor = max(1, int(max(w, h) / 48))
                img = img.subsample(factor, factor)
            logo_lbl = ttk.Label(dlg, image=img, background=BG)
            logo_lbl.image = img  # prevent garbage collection
            logo_lbl.pack(pady=(18, 4))
        except Exception:
            pass  # Logo is optional; the dialog looks fine without it.

        # ---- App name and version ----
        ttk.Label(
            dlg, text="Password Manager",
            style="Header.TLabel",
        ).pack()
        ttk.Label(
            dlg, text=f"Version {APP_VERSION}",
            style="Small.TLabel",
        ).pack(pady=(0, 10))

        # ---- Thin horizontal rule ----
        ttk.Separator(dlg, orient="horizontal").pack(fill="x", padx=20, pady=(0, 10))

        # ---- Description ----
        ttk.Label(
            dlg,
            text="A secure, encrypted password manager\nfor Windows, macOS and Linux.",
            style="App.TLabel",
            justify="center",
        ).pack(padx=20)

        # ---- Author ----
        ttk.Label(
            dlg, text="\nAuthor:  Dragos Burcut",
            style="App.TLabel",
        ).pack()

        # ---- GitHub link (clickable) ----
        link_frame = Frame(dlg, bg=BG)
        link_frame.pack(pady=(4, 0))
        ttk.Label(link_frame, text="GitHub:", style="App.TLabel").pack(side="left")

        # Create a label that looks and behaves like a hyperlink.
        try:
            link_font = tkfont.Font(family="Segoe UI", size=10, underline=True)
        except Exception:
            link_font = None

        link_kwargs = dict(
            text=REPO_URL,
            foreground="#1a6fb5",
            background=BG,
            cursor="hand2",
            font=link_font,
        )
        link_lbl = Label(link_frame, **link_kwargs)
        link_lbl.pack(side="left", padx=(6, 0))

        def _open_link(_event=None):
            try:
                webbrowser.open(REPO_URL)
            except Exception:
                pass

        link_lbl.bind("<Button-1>", _open_link)

        # ---- Built-with info ----
        py_ver = f"{_sys.version_info.major}.{_sys.version_info.minor}.{_sys.version_info.micro}"
        ttk.Label(
            dlg,
            text=f"\nBuilt with Python {py_ver} · Tkinter · cryptography",
            style="Small.TLabel",
            justify="center",
        ).pack()

        # ---- Close button ----
        ttk.Separator(dlg, orient="horizontal").pack(fill="x", padx=20, pady=(14, 0))
        ttk.Button(
            dlg, text="Close", style="App.TButton", command=dlg.destroy,
        ).pack(pady=10)

        # Centre the dialog on the parent window.
        dlg.update_idletasks()
        pw = self.root.winfo_x() + self.root.winfo_width()  // 2
        ph = self.root.winfo_y() + self.root.winfo_height() // 2
        dw = dlg.winfo_width()
        dh = dlg.winfo_height()
        dlg.geometry(f"+{pw - dw // 2}+{ph - dh // 2}")

        dlg.wait_window()

    @staticmethod
    def _check_for_updates() -> None:
        """
        Open the project's GitHub page in the default web browser so the
        user can check for new releases and download updates manually.
        """
        url = "https://github.com/BurcutDragos/Simple-Password-Manager-Application"
        try:
            webbrowser.open(url)
        except Exception:
            logger.exception("Failed to open browser for update check")
            messagebox.showwarning(
                "Could not open browser",
                f"Please visit manually:\n{url}",
            )

    def _on_closing(self) -> None:
        """
        Called when the user clicks the window close button (X).

        Saves the current configuration, logs the close event, cleans up
        any temporary decrypted files, and destroys the root window.
        """
        self.config.save()
        logger.info("Application closed")
        self.crypto.cleanup_temp_files()
        self.root.destroy()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the Tkinter event loop.

        This call blocks until the window is closed by the user.
        """
        self.root.mainloop()
