"""
CipherDrop Desktop Client (PySide6 Port)

This file is a port of the Streamlit application to a desktop app
using PySide6 (Qt).

It requires the same dependencies as the original:
- PySide6
- requests
- And your local crypto libraries:
  - auth.keys
  - crypto.supertext
  - crypto.files
  - stego.png_lsb

Run this file from the *same project root* as your original
streamlit_app.py so that the local imports can be found.
"""
import base64
import json
import os
import sys
import tempfile
import pathlib
from dataclasses import dataclass
from typing import Optional, Callable
import traceback
import asyncio
import keyring

# for pyinstall
# Resolve paths both in normal Python and PyInstaller (_MEIPASS)
ROOT = pathlib.Path(__file__).resolve().parent
BASE = pathlib.Path(getattr(sys, "_MEIPASS", ROOT))   # <- bundle dir at runtime

# Make bundled packages importable (auth/, crypto/, stego/)
sys.path.insert(0, str(BASE))
# --- END OF ADDED CODE ---

# --- Qt Imports ---
from PySide6.QtCore import (
    QObject, Signal, Slot, QRunnable, QThreadPool, Qt, QStandardPaths
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTabWidget, QLabel, QTextEdit, QSpinBox,
    QCheckBox, QFileDialog, QMessageBox, QStatusBar, QScrollArea,
    QGroupBox, QFrame, QGridLayout, QFormLayout, QDialog
)
from PySide6.QtGui import QIcon, QPixmap, QFont

# --- Add app data paths ---
CONFIG_DIR = pathlib.Path(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)) / "CipherDrop"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# --- Networking ---
import requests

# --- Local crypto imports (from your project tree) ---
# Ensure you run this app from the project root so these imports resolve.
try:
    from auth.keys import derive_key_from_password, ARGON_PARAMS
    from crypto.supertext import super_encrypt_text, super_decrypt_text
    from crypto.files import aesgcm_encrypt_file_with_passphrase, aesgcm_decrypt_bytes_with_passphrase
    from stego.png_lsb import hide_to_png, reveal_from_png
except ImportError:
    print("ERROR: Could not import local crypto libraries.")
    print("Please run this script from your project's root directory.")
    print("This app will crash if the imports are not found.")
    # We'll let it crash later if they try to use it,
    # but this provides an initial warning.
    pass

try:
    from winrt.windows.security.credentials.ui import UserConsentVerifier, UserConsentVerifierAvailability
    from winrt.windows.security.credentials.ui import UserConsentVerificationResult
except ImportError:
    print("WARNING: winrt-windows library not found. Biometric login will be disabled.")
    UserConsentVerifier = None # So the app doesn't crash

# ----------------------------------------------------------------------
# ASYNCHRONOUS WORKER
# This is the most critical part of a desktop port.
# We CANNOT run `requests` calls on the main UI thread,
# as it will freeze the entire application.
#
# This Worker system runs any function in a background
# thread and "emits" a signal when it's done (either
# with the result or an error).
# ----------------------------------------------------------------------

class WorkerSignals(QObject):
    """
    Defines the signals available from a running worker thread.
    - success: Emits the return value of the function.
    - error: Emits the exception object if one occurred.
    - finished: Emits when the worker is done.
    """
    success = Signal(object)
    error = Signal(Exception)
    finished = Signal()

class Worker(QRunnable):
    """
    Worker thread that runs a function with given args/kwargs.
    """
    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self):
        """Execute the function and emit signals."""
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as e:
            # print(f"Worker error: {e}")
            # traceback.print_exc()
            self.signals.error.emit(e)
        else:
            self.signals.success.emit(result)
        finally:
            self.signals.finished.emit()


# ----------------------------------------------------------------------
# API CLIENT & HELPERS
# (Copied directly from streamlit_app.py)
# ----------------------------------------------------------------------

@dataclass
class Session:
    api: str
    token: Optional[str] = None
    username: Optional[str] = None

    @property
    def headers(self):
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}


def api_register(sess: Session, username: str, password: str):
    r = requests.post(f"{sess.api}/auth/register", json={"username": username, "password": password})
    if r.status_code == 409:
        return False, "Username already exists"
    r.raise_for_status()
    return True, "Registered"


def api_login(sess: Session, username: str, password: str):
    r = requests.post(f"{sess.api}/auth/login", json={"username": username, "password": password})
    if r.status_code != 200:
        return None
    tok = r.json().get("token")
    return tok


def api_send_json(sess: Session, to_user: str, filename: str, mime: str, payload_bytes: bytes, ttl_min: int = 30, one_time: bool = True):
    b64 = base64.b64encode(payload_bytes).decode()
    r = requests.post(
        f"{sess.api}/api/send-json",
        headers=sess.headers,
        json={
            "to": to_user,
            "payload_b64": b64,
            "filename": filename,
            "mime": mime,
            "ttl_min": ttl_min,
            "one_time": one_time,
        },
    )
    r.raise_for_status() # Let worker catch non-200s
    return r


def api_inbox(sess: Session):
    r = requests.get(f"{sess.api}/api/inbox", headers=sess.headers)
    r.raise_for_status()
    return r.json()

def api_recv64(sess: Session, item_id: str) -> dict:
    r = requests.get(f"{sess.api}/api/recv64/{item_id}", headers=sess.headers)
    if r.status_code != 200:
        raise RuntimeError(f"{r.status_code}: {r.text}")
    return r.json()


def api_recv(sess: Session, item_id: str) -> bytes:
    r = requests.get(f"{sess.api}/api/recv/{item_id}", headers=sess.headers)
    if r.status_code != 200:
        raise RuntimeError(r.text)
    return r.content

# --- ADDED: API function for deleting ---
def api_delete_item(sess: Session, item_id: str):
    """Calls the DELETE endpoint for an item."""
    r = requests.delete(f"{sess.api}/api/recv/{item_id}", headers=sess.headers)
    r.raise_for_status() # Let worker catch non-200s
    return r.json() # Should return {"ok": True}
# --- END ADD ---


# --- UI Helpers ---

def reveal_env_from_png_bytes(png_bytes: bytes) -> dict:
    """
    Write PNG bytes to a temp file and reveal the hidden JSON envelope.
    Returns the envelope (dict). Raises ValueError if nothing found.
    """
    tmp = pathlib.Path(tempfile.gettempdir()) / "inbox_reveal.png"
    tmp.write_bytes(png_bytes)
    env = reveal_from_png(str(tmp))  # -> dict (your stego util decodes base64+json)
    if not isinstance(env, dict) or "ct_b64" not in env:
        raise ValueError("No hidden envelope found in PNG.")
    return env

# ----------------------------------------------------------------------
# MAIN APPLICATION WINDOW
# ----------------------------------------------------------------------

class MainWindow(QMainWindow):
    CONFIG_FILE = CONFIG_DIR / "app_config.json"  # Now uses the app data directory
    
    def _read_app_config(self) -> dict:
        """Reads the app config JSON, returns defaults if not found."""
        try:
            if self.CONFIG_FILE.exists():
                config_data = json.loads(self.CONFIG_FILE.read_text())
                return config_data
        except Exception as e:
            print(f"Error reading config file: {e}")
        
        # Return defaults
        return {"last_user": None, "biometrics_enabled": False}

    def _write_app_config(self, config: dict):
        """Writes the config dict to the JSON file."""
        try:
            self.CONFIG_FILE.write_text(json.dumps(config, indent=2))
        except Exception as e:
            print(f"Error writing config file: {e}")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CipherDrop")
        self.setGeometry(100, 100, 900, 700)
        
        # Load and set window icon
        icon_path = BASE / "icon/Cyber-Cage.png"  # Relative to bundled resources
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        # --- App State ---
        self.session = Session(api=os.environ.get("CIPHERDROP_API",  "https://fyuko.dev"))
        self.threadpool = QThreadPool()
        self.running_workers = set()
        
        # --- Store file paths for uploads ---
        self.send_file_path = None
        self.stego_cover_png_path = None
        self.stego_local_png_path = None

        # --- Init UI ---
        self.init_ui()
        self.update_ui_for_login_status()
        self.try_biometric_login()

    def on_biometrics_toggle(self, state: int):
        """Handle the biometrics checkbox state change."""
        if not self.session.username:  # Safety check
            return
            
        config = self._read_app_config()
        is_enabled = state == Qt.CheckState.Checked.value
        config["biometrics_enabled"] = is_enabled
        
        try:
            if is_enabled:
                # Save the current token for biometric login
                keyring.set_password("CipherDrop", self.session.username, self.session.token)
                print(f"Biometrics enabled. Saved token for {self.session.username}")
            else:
                # Delete any saved token
                keyring.delete_password("CipherDrop", self.session.username)
                print(f"Biometrics disabled. Removed token for {self.session.username}")
        except Exception as e:
            print(f"Error managing keyring: {e}")
            # If we couldn't save/delete the token, don't enable biometrics
            if is_enabled:
                config["biometrics_enabled"] = False
                self.biometrics_toggle_check.setChecked(False)
        
        self._write_app_config(config)
        
    # vvvv ADD THIS NEW METHOD vvvv
    def run_biometric_check(self) -> bool:
        """
        Runs the Windows Hello biometric check.
        Returns True if successful, False otherwise.
        """
        if not UserConsentVerifier:
            print("Biometric check skipped (winrt library not loaded).")
            return False

        async def check_async():
            try:
                # 1. Check if biometrics are even set up
                availability = await UserConsentVerifier.check_availability_async()
                if availability != UserConsentVerifierAvailability.AVAILABLE:
                    print("Biometrics not available.")
                    return False

                # 2. Pop the Windows Hello dialog
                prompt = "Sign in to CipherDrop"
                result = await UserConsentVerifier.request_verification_async(prompt)
                
                # 3. Check the result
                return result == UserConsentVerificationResult.VERIFIED
                
            except Exception as e:
                print(f"Biometric check failed: {e}")
                return False

        # Run the async function from our sync code
        try:
            # This is the simplest way to run it.
            return asyncio.run(check_async())
        except RuntimeError as e:
            # This can happen if an event loop is already running
            print(f"Could not run biometric check: {e}")
            return False
    # ^^^^ END OF NEW METHOD ^^^^
    
    def try_biometric_login(self):
        """Checks for a saved token and attempts biometric unlock."""
        if self.session.token:
            return

        try:
            config = self._read_app_config()
            username = config.get("last_user")
            biometrics_enabled = config.get("biometrics_enabled", False)

            if not username or not biometrics_enabled:
                # No last user or biometrics are explicitly disabled
                if not biometrics_enabled:
                    print("Biometric login disabled by user preference.")
                return

            print(f"Found last user: {username}")
            saved_token = keyring.get_password("CipherDrop", username)

            if saved_token:
                print("Found saved token. Requesting biometric unlock...")
                if self.run_biometric_check():
                    print("Biometric unlock successful!")
                    self.session.token = saved_token
                    self.session.username = username
                    self.update_ui_for_login_status()
                else:
                    print("Biometric unlock failed or was cancelled.")
            else:
                print("No token found in keyring for last user (may have been deleted).")
                
        except Exception as e:
            print(f"Error during biometric login attempt: {e}")

    def init_ui(self):
        # --- Main Layout ---
        self.central_widget = QWidget()
        self.main_layout = QHBoxLayout(self.central_widget)
        self.setCentralWidget(self.central_widget)

        # --- Status Bar ---
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Please log in.")

        # --- Create Sidebar ---
        self.sidebar_frame = self.create_sidebar()
        self.main_layout.addWidget(self.sidebar_frame)
        self.sidebar_frame.setMinimumWidth(250)
        self.sidebar_frame.setMaximumWidth(300)

        # --- Create Main Tabs ---
        self.main_tabs = self.create_main_tabs()
        self.main_layout.addWidget(self.main_tabs, 1) # Add with stretch factor

    def create_sidebar(self) -> QFrame:
        """Creates the left-hand sidebar for auth and settings."""
        sidebar_frame = QFrame()
        sidebar_frame.setFrameShape(QFrame.Shape.StyledPanel)
        sidebar_layout = QVBoxLayout(sidebar_frame)

        # --- Server Settings ---
        server_group = QGroupBox("Server")
        server_layout = QFormLayout()
        self.api_url_edit = QLineEdit(self.session.api)
        self.api_url_edit.editingFinished.connect(self.on_api_url_changed)
        server_layout.addRow("API URL:", self.api_url_edit)
        server_group.setLayout(server_layout)
        sidebar_layout.addWidget(server_group)

        # --- Account ---
        self.account_group = QGroupBox("Account")
        self.account_layout = QVBoxLayout() # This will hold one of two widgets
        self.account_group.setLayout(self.account_layout)
        sidebar_layout.addWidget(self.account_group)

        # --- Logged Out Widget ---
        self.logged_out_widget = QWidget()
        logged_out_layout = QVBoxLayout(self.logged_out_widget)
        logged_out_layout.setContentsMargins(0,0,0,0)
        
        auth_tabs = QTabWidget()
        login_tab = QWidget()
        reg_tab = QWidget()
        
        # Login Tab
        login_layout = QFormLayout(login_tab)
        self.login_user_edit = QLineEdit()
        # Pre-fill with last username if available
        config = self._read_app_config()
        if last_user := config.get("last_user"):
            self.login_user_edit.setText(last_user)
            
        self.login_pass_edit = QLineEdit(echoMode=QLineEdit.Password)
        self.login_button = QPushButton("Login")
        login_layout.addRow("Username:", self.login_user_edit)
        login_layout.addRow("Password:", self.login_pass_edit)
        login_layout.addWidget(self.login_button)
        
        # Register Tab
        reg_layout = QFormLayout(reg_tab)
        self.reg_user_edit = QLineEdit()
        self.reg_pass_edit = QLineEdit(echoMode=QLineEdit.Password)
        self.reg_pass_confirm_edit = QLineEdit(echoMode=QLineEdit.Password)
        self.reg_button = QPushButton("Create Account")
        reg_layout.addRow("New Username:", self.reg_user_edit)
        reg_layout.addRow("New Password:", self.reg_pass_edit)
        reg_layout.addRow("Confirm Password:", self.reg_pass_confirm_edit)
        reg_layout.addWidget(self.reg_button)

        auth_tabs.addTab(login_tab, "Login")
        auth_tabs.addTab(reg_tab, "Register")
        logged_out_layout.addWidget(auth_tabs)
        
        # --- Logged In Widget ---
        self.logged_in_widget = QWidget()
        logged_in_layout = QVBoxLayout(self.logged_in_widget)
        logged_in_layout.setContentsMargins(0,0,0,0)
        self.logged_in_label = QLabel("Signed in as...")
        self.logged_in_label.setWordWrap(True)
        
        # Add biometrics toggle checkbox
        self.biometrics_toggle_check = QCheckBox("Enable Biometric Unlock")
        self.biometrics_toggle_check.setChecked(False)  # We'll load the real value later
        self.biometrics_toggle_check.stateChanged.connect(self.on_biometrics_toggle)

        self.logout_button = QPushButton("Logout")
        logged_in_layout.addWidget(self.logged_in_label)
        logged_in_layout.addWidget(self.biometrics_toggle_check)
        logged_in_layout.addWidget(self.logout_button)

        # Add both to account layout and hide one
        self.account_layout.addWidget(self.logged_out_widget)
        self.account_layout.addWidget(self.logged_in_widget)
        self.logged_in_widget.hide()

        sidebar_layout.addStretch() # Pushes everything up

        # --- Connect Signals ---
        self.logout_button.clicked.connect(self.do_logout)
        self.login_button.clicked.connect(self.do_login)
        self.reg_button.clicked.connect(self.do_register)

        return sidebar_frame

    def create_main_tabs(self) -> QTabWidget:
        """Creates the main QTabWidget for app functionality."""
        tabs = QTabWidget()
        tabs.addTab(self.create_inbox_tab(), "Inbox")
        tabs.addTab(self.create_compose_tab(), "Compose")
        tabs.addTab(self.create_stego_decrypt_tab(), "Local Decrypt")
        
        # Disable tabs until logged in
        tabs.setEnabled(False)
        return tabs

    # ---------------------------------
    # --- Tab Creation Methods ---
    # ---------------------------------

    def create_compose_tab(self) -> QWidget:
        """Creates the 'Compose' tab, which contains sub-tabs for sending."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create sub-tabs for all "send" actions
        compose_tabs = QTabWidget()
        compose_tabs.addTab(self.create_send_text_tab(), "Send Text")
        compose_tabs.addTab(self.create_send_file_tab(), "Send File")
        compose_tabs.addTab(self.create_stego_tab(), "Image Stego")
        
        layout.addWidget(compose_tabs)
        return widget

    def create_send_text_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        header = QLabel("Encrypt & Send Text")
        header.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        layout.addWidget(header)

        # --- Form ---
        form_layout = QGridLayout()
        self.send_to_user_edit = QLineEdit()
        self.send_passphrase_edit = QLineEdit(echoMode=QLineEdit.Password)
        self.send_vkey_edit = QLineEdit("CRYPTO")
        self.send_ttl_spinbox = QSpinBox(minimum=5, maximum=1440, value=30, singleStep=5)
        self.send_onetime_check = QCheckBox("One-time read (delete after first open)")
        self.send_onetime_check.setChecked(False)
        
        form_layout.addWidget(QLabel("Recipient Username:"), 0, 0)
        form_layout.addWidget(self.send_to_user_edit, 0, 1)
        form_layout.addWidget(QLabel("Shared Passphrase:"), 1, 0)
        form_layout.addWidget(self.send_passphrase_edit, 1, 1)
        form_layout.addWidget(QLabel("Vigenère Key:"), 0, 2)
        form_layout.addWidget(self.send_vkey_edit, 0, 3)
        form_layout.addWidget(QLabel("TTL (minutes):"), 1, 2)
        form_layout.addWidget(self.send_ttl_spinbox, 1, 3)
        form_layout.addWidget(self.send_onetime_check, 2, 0, 1, 4)
        
        layout.addLayout(form_layout)
        
        # --- Message ---
        layout.addWidget(QLabel("Message:"))
        self.send_message_text = QTextEdit(placeholderText="Type your secret here…")
        self.send_message_text.setMinimumHeight(150)
        layout.addWidget(self.send_message_text)
        
        # --- Send Button ---
        self.send_text_button = QPushButton("Encrypt & Send")
        self.send_text_button.clicked.connect(self.do_send_text)
        layout.addWidget(self.send_text_button)
        
        layout.addStretch()
        return widget

    def create_inbox_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        header_layout = QHBoxLayout()
        header = QLabel("Inbox")
        header.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        header_layout.addWidget(header)
        header_layout.addStretch()
        self.refresh_inbox_button = QPushButton("Refresh Inbox")
        self.refresh_inbox_button.setObjectName("refresh_inbox_button") # For styling
        self.refresh_inbox_button.clicked.connect(self.do_refresh_inbox)
        header_layout.addWidget(self.refresh_inbox_button)
        
        layout.addLayout(header_layout)

        # --- Scroll Area for Inbox Items ---
        self.inbox_scroll_area = QScrollArea()
        self.inbox_scroll_area.setWidgetResizable(True)
        self.inbox_container = QWidget()
        self.inbox_layout = QVBoxLayout(self.inbox_container)
        self.inbox_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.inbox_scroll_area.setWidget(self.inbox_container)
        
        layout.addWidget(self.inbox_scroll_area)
        
        self.inbox_layout.addWidget(QLabel("Press 'Refresh Inbox' to load messages."))
        
        return widget

    def create_send_file_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        header = QLabel("Encrypt & Send File")
        header.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        layout.addWidget(header)

        form_layout = QFormLayout()
        self.file_to_user_edit = QLineEdit()
        self.file_passphrase_edit = QLineEdit(echoMode=QLineEdit.Password)
        self.file_ttl_spinbox = QSpinBox(minimum=5, maximum=1440, value=30, singleStep=5)
        self.file_onetime_check = QCheckBox("One-time read")
        self.file_onetime_check.setChecked(False)
        
        form_layout.addRow("Recipient Username:", self.file_to_user_edit)
        form_layout.addRow("Shared Passphrase:", self.file_passphrase_edit)
        form_layout.addRow("TTL (minutes):", self.file_ttl_spinbox)
        form_layout.addRow(self.file_onetime_check)
        
        layout.addLayout(form_layout)
        
        # --- File Picker ---
        file_picker_layout = QHBoxLayout()
        self.file_select_button = QPushButton("Select File...")
        self.file_select_button.clicked.connect(self.on_select_send_file)
        self.file_path_label = QLabel("No file selected.")
        file_picker_layout.addWidget(self.file_select_button)
        file_picker_layout.addWidget(self.file_path_label, 1)
        layout.addLayout(file_picker_layout)

        self.send_file_button = QPushButton("Encrypt & Send File")
        self.send_file_button.clicked.connect(self.do_send_file)
        layout.addWidget(self.send_file_button)
        layout.addStretch()
        return widget
        
    def create_stego_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        header = QLabel("Hide Ciphertext Inside PNG")
        header.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        layout.addWidget(header)

        # --- Form ---
        form_layout = QFormLayout()
        self.stego_to_user_edit = QLineEdit()
        self.stego_passphrase_edit = QLineEdit(echoMode=QLineEdit.Password)
        self.stego_vkey_edit = QLineEdit("CRYPTO")
        self.stego_ttl_spinbox = QSpinBox(minimum=5, maximum=1440, value=30, singleStep=5)
        self.stego_onetime_check = QCheckBox("One-time read")
        self.stego_onetime_check.setChecked(False)

        form_layout.addRow("Recipient Username:", self.stego_to_user_edit)
        form_layout.addRow("Shared Passphrase:", self.stego_passphrase_edit)
        form_layout.addRow("Vigenère Key:", self.stego_vkey_edit)
        form_layout.addRow("TTL (minutes):", self.stego_ttl_spinbox)
        form_layout.addRow(self.stego_onetime_check)
        layout.addLayout(form_layout)

        # --- PNG Picker ---
        png_picker_layout = QHBoxLayout()
        self.stego_select_png_button = QPushButton("Select Cover PNG...")
        self.stego_select_png_button.clicked.connect(self.on_select_stego_cover)
        self.stego_png_path_label = QLabel("No PNG selected.")
        png_picker_layout.addWidget(self.stego_select_png_button)
        png_picker_layout.addWidget(self.stego_png_path_label, 1)
        layout.addLayout(png_picker_layout)
        
        # --- Message ---
        layout.addWidget(QLabel("Text to Hide:"))
        self.stego_message_text = QTextEdit(placeholderText="Type your secret here…")
        self.stego_message_text.setMinimumHeight(100)
        layout.addWidget(self.stego_message_text)
        
        # --- Send Button ---
        self.stego_send_button = QPushButton("Encrypt → Hide → Send PNG")
        self.stego_send_button.clicked.connect(self.do_send_stego)
        layout.addWidget(self.stego_send_button)
        layout.addStretch()
        
        return widget

    def create_stego_decrypt_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        header = QLabel("Reveal & Decrypt from a Local PNG")
        header.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # --- PNG Picker ---
        png_picker_layout = QHBoxLayout()
        self.stego_local_select_button = QPushButton("Select PNG File...")
        self.stego_local_select_button.clicked.connect(self.on_select_stego_local)
        self.stego_local_path_label = QLabel("No PNG selected.")
        png_picker_layout.addWidget(self.stego_local_select_button)
        png_picker_layout.addWidget(self.stego_local_path_label, 1)
        layout.addLayout(png_picker_layout)

        # --- Image Preview ---
        self.stego_local_preview = QLabel("PNG preview will appear here.")
        self.stego_local_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.stego_local_preview.setMinimumHeight(200)
        self.stego_local_preview.setFrameShape(QFrame.Shape.StyledPanel)
        layout.addWidget(self.stego_local_preview)

        # --- Form ---
        form_layout = QFormLayout()
        self.stego_local_passphrase_edit = QLineEdit(echoMode=QLineEdit.Password)
        self.stego_local_vkey_edit = QLineEdit("CRYPTO")
        form_layout.addRow("Passphrase:", self.stego_local_passphrase_edit)
        form_layout.addRow("Vigenère Key:", self.stego_local_vkey_edit)
        layout.addLayout(form_layout)
        
        self.stego_local_reveal_button = QPushButton("Reveal & Decrypt")
        self.stego_local_reveal_button.clicked.connect(self.do_reveal_stego_local)
        layout.addWidget(self.stego_local_reveal_button)
        layout.addStretch()
        
        return widget

    # ---------------------------------
    # --- UI State & Helper Methods ---
    # ---------------------------------

    def update_ui_for_login_status(self):
        """Show/hide widgets based on login state."""
        is_logged_in = self.session.token is not None
        
        self.logged_in_widget.setVisible(is_logged_in)
        self.logged_out_widget.setVisible(not is_logged_in)
        self.main_tabs.setEnabled(is_logged_in)
        
        if is_logged_in:
            self.logged_in_label.setText(f"Signed in as:\n**{self.session.username}**")
            
            # Set the checkbox state from config
            config = self._read_app_config()
            self.biometrics_toggle_check.setChecked(config.get("biometrics_enabled", False))
            
            self.statusBar().showMessage("Ready.")
            # Auto-refresh inbox on login
            self.do_refresh_inbox()
        else:
            self.statusBar().showMessage("Please log in.")
            # Clear inbox
            self.clear_inbox_layout()
            self.inbox_layout.addWidget(QLabel("Please log in to see your inbox."))

    def clear_inbox_layout(self):
        """Removes all widgets from the inbox layout."""
        while self.inbox_layout.count():
            child = self.inbox_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
    
    def on_api_url_changed(self):
        """Update the session API URL when the text edit is done."""
        new_api = self.api_url_edit.text()
        if new_api != self.session.api:
            self.do_logout()
            self.session.api = new_api
            self.statusBar().showMessage(f"API URL set. Please log in.")
    
    def on_select_send_file(self):
        """Open file dialog for 'Send File' tab."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if path:
            self.send_file_path = path
            self.file_path_label.setText(os.path.basename(path))
    
    def on_select_stego_cover(self):
        """Open file dialog for 'Image Stego' tab."""
        path, _ = QFileDialog.getOpenFileName(self, "Select Cover PNG", filter="PNG Files (*.png)")
        if path:
            self.stego_cover_png_path = path
            self.stego_png_path_label.setText(os.path.basename(path))
    
    def on_select_stego_local(self):
        """Open file dialog for 'Stego Decrypt' tab and show preview."""
        path, _ = QFileDialog.getOpenFileName(self, "Select PNG to Reveal", filter="PNG Files (*.png)")
        if path:
            self.stego_local_png_path = path
            self.stego_local_path_label.setText(os.path.basename(path))
            
            # Show preview
            pixmap = QPixmap(path)
            if pixmap.isNull():
                self.stego_local_preview.setText("Could not load image preview.")
            else:
                self.stego_local_preview.setPixmap(
                    pixmap.scaled(
                        self.stego_local_preview.width() - 10, 
                        200, 
                        Qt.AspectRatioMode.KeepAspectRatio, 
                        Qt.TransformationMode.SmoothTransformation
                    )
                )

    def show_error(self, title: str, text: str):
        """Helper to show a critical error message box."""
        QMessageBox.critical(self, title, str(text))
        self.statusBar().showMessage(f"Error: {text}")
        
    def show_success(self, title: str, text: str):
        """Helper to show an information message box."""
        QMessageBox.information(self, title, str(text))
        self.statusBar().showMessage(f"Success: {text}")

    @Slot(QRunnable)
    def on_worker_finished(self, worker):
        """
        Slot to be called when a worker is finished.
        Removes the worker from the set to allow garbage collection.
        """
        try:
            self.running_workers.remove(worker)
        except KeyError:
            pass # Should not happen, but safe to ignore

    # ---------------------------------
    # --- "DO" METHODS (GUI -> Worker) ---
    # ---------------------------------

    @Slot()
    def do_logout(self):
        """Logs the user out and resets UI."""
        
        if self.session.username:
            # Save the username in config before logout (but don't change other settings)
            config = self._read_app_config()
            config["last_user"] = self.session.username
            self._write_app_config(config)
            
            # Delete the stored token if it exists
            try:
                keyring.delete_password("CipherDrop", self.session.username)
                print(f"Logged out. Removed token for {self.session.username}.")
            except keyring.errors.NoKeyringError:
                print("No keyring service found to delete from.")
            except keyring.errors.PasswordDeleteError:
                print(f"No token found for {self.session.username} to delete, or delete failed.")
            except Exception as e:
                print(f"Error deleting token from keyring on logout: {e}")

        self.session.token = None
        self.session.username = None
        self.update_ui_for_login_status()
        self.statusBar().showMessage("Logged out.")

    @Slot()
    def do_login(self):
        """Starts the login worker thread."""
        username = self.login_user_edit.text()
        password = self.login_pass_edit.text()
        if not username or not password:
            self.show_error("Login Failed", "Username and password are required.")
            return

        self.statusBar().showMessage("Logging in...")
        self.login_button.setEnabled(False)
        
        worker = Worker(api_login, self.session, username, password)
        # Pass along username so the success slot knows who logged in
        worker.signals.success.connect(lambda token: self.on_login_success(token, username))
        worker.signals.error.connect(self.on_login_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.login_button.setEnabled(True))
        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot()
    def do_register(self):
        """Starts the register worker thread."""
        username = self.reg_user_edit.text()
        password = self.reg_pass_edit.text()
        confirm_password = self.reg_pass_confirm_edit.text()
        
        if not username or not password:
            self.show_error("Registration Failed", "Username and password are required.")
            return
            
        if password != confirm_password:
            self.show_error("Registration Failed", "Passwords do not match. Please try again.")
            return

        self.statusBar().showMessage("Registering...")
        self.reg_button.setEnabled(False)
        
        worker = Worker(api_register, self.session, username, password)
        worker.signals.success.connect(self.on_register_success)
        worker.signals.error.connect(self.on_register_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.reg_button.setEnabled(True))
        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot()
    def do_send_text(self):
        """Validates form and starts the send_text worker."""
        to_user = self.send_to_user_edit.text()
        passphrase = self.send_passphrase_edit.text()
        message = self.send_message_text.toPlainText()
        vkey = self.send_vkey_edit.text()
        ttl = self.send_ttl_spinbox.value()
        one_time = self.send_onetime_check.isChecked()

        if not to_user or not passphrase or not message:
            self.show_error("Send Failed", "Recipient, passphrase, and message are required.")
            return

        self.statusBar().showMessage("Encrypting and sending...")
        self.send_text_button.setEnabled(False)
        
        # This crypto task can also be moved to the worker
        # But for now, we do it here. If it's slow, move it.
        try:
            dk = derive_key_from_password(passphrase)
            env = super_encrypt_text(message, vkey, dk.key)
            env["kdf"] = {
                "type": "argon2id",
                "salt_b64": base64.b64encode(dk.salt).decode(),
                "t": ARGON_PARAMS["time_cost"],
                "m": ARGON_PARAMS["memory_cost"],
                "p": ARGON_PARAMS["parallelism"],
            }
            blob = json.dumps(env, ensure_ascii=False).encode()
        except Exception as e:
            self.show_error("Encryption Failed", f"Could not encrypt message: {e}")
            self.send_text_button.setEnabled(True)
            return

        worker = Worker(api_send_json, self.session, to_user, "message.json", "application/json", blob, ttl, one_time)
        worker.signals.success.connect(self.on_send_text_success)
        worker.signals.error.connect(self.on_send_text_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.send_text_button.setEnabled(True))
        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot()
    def do_refresh_inbox(self):
        """Starts the inbox refresh worker."""
        self.statusBar().showMessage("Refreshing inbox...")
        self.refresh_inbox_button.setEnabled(False)
        
        worker = Worker(api_inbox, self.session)
        worker.signals.success.connect(self.on_inbox_success)
        worker.signals.error.connect(self.on_inbox_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.refresh_inbox_button.setEnabled(True))
        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot()
    def do_send_file(self):
        """Validates and starts the send_file worker."""
        to_user = self.file_to_user_edit.text()
        passphrase = self.file_passphrase_edit.text()
        file_path = self.send_file_path
        
        if not to_user or not passphrase or not file_path:
            self.show_error("Send Failed", "Recipient, passphrase, and a selected file are required.")
            return

        self.statusBar().showMessage("Encrypting and sending file...")
        self.send_file_button.setEnabled(False)

        # We need to run the *entire* process in a worker,
        # including file I/O and encryption.
        
        # Create a new function for the worker to run
        def send_file_task(sess, to, pw, path, ttl, one_time):
            src = pathlib.Path(path)
            outp = src.with_suffix(src.suffix + ".enc")
            
            # 1. Encrypt file
            aesgcm_encrypt_file_with_passphrase(pw, str(src), str(outp))
            
            # 2. Upload encrypted file
            try:
                with open(outp, "rb") as f_enc:
                    files = {"file": (outp.name, f_enc.read(), "application/octet-stream")}
                    r = requests.post(f"{sess.api}/api/send-file",
                                      headers=sess.headers,
                                      data={"to": to, "ttl_min": int(ttl), "one_time": str(one_time).lower()},
                                      files=files)
                r.raise_for_status()
                return r.json()
            finally:
                # 3. Clean up .enc file
                if outp.exists():
                    os.remove(outp)

        # --- Start worker ---
        worker = Worker(
            send_file_task,
            self.session,
            to_user,
            passphrase,
            file_path,
            self.file_ttl_spinbox.value(),
            self.file_onetime_check.isChecked()
        )
        worker.signals.success.connect(self.on_send_file_success)
        worker.signals.error.connect(self.on_send_file_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.send_file_button.setEnabled(True))
        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot()
    def do_send_stego(self):
        """Validates and starts the stego_send worker."""
        to_user = self.stego_to_user_edit.text()
        passphrase = self.stego_passphrase_edit.text()
        vkey = self.stego_vkey_edit.text()
        message = self.stego_message_text.toPlainText()
        cover_path = self.stego_cover_png_path
        
        if not (to_user and passphrase and vkey and message and cover_path):
            self.show_error("Send Failed", "All fields and a cover PNG are required.")
            return

        self.statusBar().showMessage("Encrypting, hiding, and sending...")
        self.stego_send_button.setEnabled(False)

        def send_stego_task(sess, to, pw, vk, msg, path, ttl, one_time):
            # 1. Encrypt text
            dk = derive_key_from_password(pw)
            env = super_encrypt_text(msg, vk, dk.key)
            env["kdf"] = {"type":"argon2id","salt_b64": base64.b64encode(dk.salt).decode()}
            
            # 2. Hide in PNG
            cover = pathlib.Path(path)
            # Use temp dir for output
            outp = pathlib.Path(tempfile.gettempdir()) / f"stego_{cover.name}"
            
            try:
                hide_to_png(str(cover), str(outp), env)
            
                # 3. Upload stego PNG
                with open(outp, "rb") as f_stego:
                    files = {"file": (outp.name, f_stego.read(), "image/png")}
                    r = requests.post(f"{sess.api}/api/send-file",
                                      headers=sess.headers,
                                      data={"to": to, "ttl_min": int(ttl), "one_time": str(one_time).lower()},
                                      files=files)
                r.raise_for_status()
                return r.json()
            finally:
                # 4. Clean up temp stego file
                if outp.exists():
                    os.remove(outp)
        
        # --- Start worker ---
        worker = Worker(
            send_stego_task,
            self.session,
            to_user,
            passphrase,
            vkey,
            message,
            cover_path,
            self.stego_ttl_spinbox.value(),
            self.stego_onetime_check.isChecked()
        )
        worker.signals.success.connect(self.on_send_stego_success)
        worker.signals.error.connect(self.on_send_stego_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.stego_send_button.setEnabled(True))
        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot()
    def do_reveal_stego_local(self):
        """Starts worker to reveal text from a local PNG."""
        file_path = self.stego_local_png_path
        passphrase = self.stego_local_passphrase_edit.text()
        vkey = self.stego_local_vkey_edit.text()
        
        if not file_path or not passphrase:
            self.show_error("Reveal Failed", "PNG file and passphrase are required.")
            return

        self.statusBar().showMessage("Revealing and decrypting...")
        self.stego_local_reveal_button.setEnabled(False)
        
        def reveal_task(path, pw, vk):
            # This is fast, but good practice to keep in worker
            png_bytes = pathlib.Path(path).read_bytes()
            env = reveal_env_from_png_bytes(png_bytes)
            salt = base64.b64decode(env["kdf"]["salt_b64"])
            dk = derive_key_from_password(pw, salt)
            clear = super_decrypt_text(env, vk, dk.key)
            return clear
        
        worker = Worker(reveal_task, file_path, passphrase, vkey)
        worker.signals.success.connect(self.on_reveal_stego_local_success)
        worker.signals.error.connect(self.on_reveal_stego_local_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.stego_local_reveal_button.setEnabled(True))
        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    # --- ADDED: Method to handle delete button click ---
    @Slot()
    def do_delete_item(self, item: dict, item_widget: QGroupBox):
        """Shows confirm dialog and starts delete worker."""
        item_id = item['id']
        
        # 1. Confirm
        reply = QMessageBox.warning(
            self,
            "Confirm Delete",
            f"Are you sure you want to permanently delete this item?\n(ID: {item_id})",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.statusBar().showMessage(f"Deleting {item_id}...")
        # Disable the widget while deleting
        item_widget.setEnabled(False)

        # 2. Define worker task
        def delete_task(sess, item_id_to_delete):
            api_delete_item(sess, item_id_to_delete)
            return item_id_to_delete # Pass id to success handler
        
        # 3. Start worker
        worker = Worker(delete_task, self.session, item_id)
        # Pass item_widget to the success/error handlers
        worker.signals.success.connect(
            lambda deleted_id: self.on_delete_item_success(deleted_id, item_widget)
        )
        worker.signals.error.connect(
            lambda e: self.on_delete_item_error(e, item_id, item_widget)
        )
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        self.running_workers.add(worker)
        self.threadpool.start(worker)
    # --- END ADD ---


    # -----------------------------------------------
    # --- "ON" METHODS (Worker -> GUI Callbacks) ---
    # -----------------------------------------------

    @Slot(object, str)
    def on_login_success(self, token, username):
        # self.login_button.setEnabled(True) # Handled by 'finished' signal
        if not token:
            self.statusBar().showMessage("Invalid credentials.")
            self.show_error("Login Failed", "Invalid username or password.")
        else:
            self.session.token = token
            self.session.username = username
            
            # Handle biometric settings
            config = self._read_app_config()  # Get existing config
            config["last_user"] = username
            
            if self.biometrics_toggle_check.isChecked():
                # User wants biometrics
                try:
                    keyring.set_password("CipherDrop", username, token)
                    config["biometrics_enabled"] = True
                    print(f"Token saved to keyring for {username}")
                except Exception as e:
                    print(f"WARNING: Could not save token to keyring: {e}")
                    config["biometrics_enabled"] = False  # Failed, so don't set it
            else:
                # User does not want biometrics
                config["biometrics_enabled"] = False
                try:
                    # Explicitly delete any old token
                    keyring.delete_password("CipherDrop", username)
                    print(f"Biometrics disabled. Removed token for {username}.")
                except keyring.errors.NoKeyringError:
                    print("No keyring service found to delete from.")
                except keyring.errors.PasswordDeleteError:
                    print(f"No token found for {username} to delete, or delete failed.")
                except Exception as e:
                    print(f"Error deleting token from keyring: {e}")

            self._write_app_config(config)
            self.update_ui_for_login_status()
            self.statusBar().showMessage("Logged in successfully.")
            
            try:
                # Save the token to Windows Credential Manager
                keyring.set_password("CipherDrop", username, token)
                # We also need to remember *who* logged in.
                # Write to app data directory
                (CONFIG_DIR / "last_user.cfg").write_text(username)
                print(f"Token saved to keyring for {username}")
            except Exception as e:
                print(f"WARNING: Could not save token to keyring: {e}")
            # ^^^^ END OF NEW BLOCK ^^^^

            self.update_ui_for_login_status()
            self.statusBar().showMessage("Logged in successfully.")

    @Slot(Exception)
    def on_login_error(self, e):
        # self.login_button.setEnabled(True) # Handled by 'finished' signal
        self.show_error("Login Error", f"Could not log in: {e}")

    @Slot(object)
    def on_register_success(self, result):
        # self.reg_button.setEnabled(True) # Handled by 'finished' signal
        ok, msg = result
        if ok:
            self.show_success("Registration Successful", "Account created. You can now log in.")
            # Clear the password fields
            self.reg_pass_edit.clear()
            self.reg_pass_confirm_edit.clear()
        else:
            self.show_error("Registration Failed", msg)

    @Slot(Exception)
    def on_register_error(self, e):
        # self.reg_button.setEnabled(True) # Handled by 'finished' signal
        self.show_error("Registration Error", f"Could not register: {e}")

    @Slot(object)
    def on_send_text_success(self, response_object):
        # self.send_text_button.setEnabled(True) # Handled by 'finished' signal
        self.show_success("Sent", f"Message sent successfully.\nID: {response_object.json().get('id')}")
        # Clear form
        self.send_message_text.clear()
        self.send_passphrase_edit.clear()

    @Slot(Exception)
    def on_send_text_error(self, e):
        # self.send_text_button.setEnabled(True) # Handled by 'finished' signal
        self.show_error("Send Error", f"Could not send message: {e}")

    @Slot(object)
    def on_inbox_success(self, inbox_list):
        # self.refresh_inbox_button.setEnabled(True) # Handled by 'finished' signal
        self.statusBar().showMessage(f"Inbox refreshed. {len(inbox_list)} items.")
        
        self.clear_inbox_layout()
        
        if not inbox_list:
            self.inbox_layout.addWidget(QLabel("Inbox is empty."))
            return
            
        for item in inbox_list:
            item_box = self.create_inbox_item_widget(item)
            self.inbox_layout.addWidget(item_box)

    @Slot(Exception)
    def on_inbox_error(self, e):
        # self.refresh_inbox_button.setEnabled(True) # Handled by 'finished' signal
        self.show_error("Inbox Error", f"Could not load inbox: {e}")

    @Slot(object)
    def on_send_file_success(self, result_json):
        # self.send_file_button.setEnabled(True) # Handled by 'finished' signal
        self.show_success("File Sent", f"Encrypted file sent.\nID: {result_json.get('id')}")
        self.file_passphrase_edit.clear()
        self.file_path_label.setText("No file selected.")
        self.send_file_path = None

    @Slot(Exception)
    def on_send_file_error(self, e):
        # self.send_file_button.setEnabled(True) # Handled by 'finished' signal
        self.show_error("Send File Error", f"Could not send file: {e}")

    @Slot(object)
    def on_send_stego_success(self, result_json):
        # self.stego_send_button.setEnabled(True) # Handled by 'finished' signal
        self.show_success("Stego PNG Sent", f"Stego image sent.\nID: {result_json.get('id')}")
        self.stego_passphrase_edit.clear()
        self.stego_message_text.clear()

    @Slot(Exception)
    def on_send_stego_error(self, e):
        # self.stego_send_button.setEnabled(True) # Handled by 'finished' signal
        self.show_error("Stego Send Error", f"Could not send stego image: {e}")
        
    @Slot(object)
    def on_reveal_stego_local_success(self, clear_text):
        # self.stego_local_reveal_button.setEnabled(True) # Handled by 'finished' signal
        self.show_success("Reveal Successful", "Decrypted text from PNG:")
        # Show in a separate, scrollable message box
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Decrypted Text")
        msg_box.setText("Decrypted text from local PNG:")
        
        scroll_area = QScrollArea(msg_box)
        scroll_area.setWidgetResizable(True)
        scroll_area.setMinimumSize(400, 200)
        
        text_widget = QTextEdit(clear_text)
        text_widget.setReadOnly(True)
        
        scroll_area.setWidget(text_widget)
        msg_box.layout().addWidget(scroll_area, 1, 0, 1, msg_box.layout().columnCount())
        
        msg_box.exec()

    @Slot(Exception)
    def on_reveal_stego_local_error(self, e):
        # self.stego_local_reveal_button.setEnabled(True) # Handled by 'finished' signal
        self.show_error("Reveal Failed", f"Could not reveal/decrypt from PNG: {e}")

    # --- ADDED: Callbacks for delete worker ---
    @Slot(str, QWidget)
    def on_delete_item_success(self, item_id: str, item_widget: QWidget):
        self.statusBar().showMessage(f"Item {item_id} deleted successfully.")
        # Remove the widget from the layout
        item_widget.setParent(None)
        item_widget.deleteLater()
        
        # Check if inbox is now empty
        if self.inbox_layout.count() == 0:
            self.inbox_layout.addWidget(QLabel("Inbox is empty."))

    @Slot(Exception, str, QWidget)
    def on_delete_item_error(self, e: Exception, item_id: str, item_widget: QWidget):
        self.show_error("Delete Failed", f"Could not delete {item_id}: {e}")
        # Re-enable the widget if it failed
        item_widget.setEnabled(True)
    # --- END ADD ---


    # ---------------------------------
    # --- DYNAMIC WIDGET CREATION ---
    # ---------------------------------

    def create_inbox_item_widget(self, item: dict) -> QGroupBox:
        """Dynamically creates a QGroupBox for an inbox item."""
        
        item_id = item['id']
        title = f"From: {item['from_user']}  ·  {item['filename'] or item['mime']}  (id: {item_id})"
        group_box = QGroupBox(title)
        group_layout = QVBoxLayout(group_box)
        
        # --- Metadata ---
        meta_layout = QGridLayout()
        meta_layout.addWidget(QLabel("Created:"), 0, 0)
        meta_layout.addWidget(QLabel(item['created_at']), 0, 1)
        meta_layout.addWidget(QLabel("Expires:"), 1, 0)
        meta_layout.addWidget(QLabel(item['expires_at']), 1, 1)
        meta_layout.addWidget(QLabel("Consumed:"), 2, 0)
        meta_layout.addWidget(QLabel(str(item['consumed'])), 2, 1)
        group_layout.addLayout(meta_layout)
        
        # --- Actions ---
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(0,0,0,0)
        
        # --- Decrypt Form ---
        decrypt_form = QWidget()
        form_layout = QFormLayout(decrypt_form)
        form_layout.setContentsMargins(0,0,0,0)
        passphrase_edit = QLineEdit(echoMode=QLineEdit.Password)
        vkey_edit = QLineEdit("CRYPTO")
        form_layout.addRow("Passphrase:", passphrase_edit)
        form_layout.addRow("Vigenère Key:", vkey_edit)
        
        # --- Action Buttons ---
        buttons_widget = QWidget()
        buttons_layout = QVBoxLayout(buttons_widget)
        buttons_layout.setContentsMargins(0,0,0,0)
        
        raw_download_btn = QPushButton("Download Raw")
        decrypt_text_btn = QPushButton("Fetch & Decrypt (Text)")
        decrypt_file_btn = QPushButton("Fetch & Decrypt (File)")
        decrypt_stego_btn = QPushButton("Reveal & Decrypt (PNG)")
        
        # --- ADDED: Delete button ---
        delete_btn = QPushButton("Delete")
        delete_btn.setObjectName("delete_button") # For styling
        # --- END ADD ---

        buttons_layout.addWidget(raw_download_btn)
        
        # --- Conditional Visibility ---
        is_text_env = (item.get("mime","").startswith("application/json")
                       or str(item.get("filename","")).lower().endswith(".json"))
        is_png = (item.get("mime","") == "image/png") or str(item.get("filename","")).lower().endswith(".png")
        
        if is_text_env:
            buttons_layout.addWidget(decrypt_text_btn)
        elif is_png:
            buttons_layout.addWidget(decrypt_stego_btn)
        else:
            # Assume file
            buttons_layout.addWidget(decrypt_file_btn)
            vkey_edit.setDisabled(True) # Not used for files

        # --- ADDED: Add delete button to layout ---
        buttons_layout.addStretch() # Pushes other buttons up
        buttons_layout.addWidget(delete_btn)
        # --- END ADD ---

        actions_layout.addWidget(decrypt_form, 1)
        actions_layout.addWidget(buttons_widget)
        group_layout.addWidget(actions_widget)
        
        # --- Connect Signals using Lambdas ---
        # This is key: the lambda captures the item and the local widgets
        
        raw_download_btn.clicked.connect(lambda: self.do_download_raw(item))
        
        decrypt_text_btn.clicked.connect(
            lambda: self.do_decrypt_item(
                item, "text", passphrase_edit.text(), vkey_edit.text()
            )
        )
        decrypt_file_btn.clicked.connect(
            lambda: self.do_decrypt_item(
                item, "file", passphrase_edit.text(), vkey_edit.text()
            )
        )
        decrypt_stego_btn.clicked.connect(
            lambda: self.do_decrypt_item(
                item, "stego", passphrase_edit.text(), vkey_edit.text()
            )
        )
        
        # --- ADDED: Connect delete button ---
        # We pass 'group_box' (the widget itself) so we can remove it on success
        delete_btn.clicked.connect(
            lambda: self.do_delete_item(item, group_box)
        )
        # --- END ADD ---
        
        return group_box

    # ---------------------------------
    # --- DYNAMIC ACTION HANDLERS ---
    # ---------------------------------

    @Slot()
    def do_download_raw(self, item: dict):
        """Starts worker to download raw bytes."""
        self.statusBar().showMessage(f"Downloading raw {item['id']}...")
        
        def task(sess, item_id):
            return api_recv(sess, item_id)
            
        worker = Worker(task, self.session, item['id'])
        worker.signals.success.connect(
            lambda data: self.on_download_raw_success(data, item.get("filename") or f"{item['id']}.bin")
        )
        worker.signals.error.connect(
            lambda e: self.show_error("Download Failed", f"Could not download {item['id']}: {e}")
        )
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot()
    def do_decrypt_item(self, item: dict, mode: str, passphrase: str, vkey: str):
        """
        Master handler for all 'decrypt' buttons in the inbox.
        Starts a worker to fetch, decrypt, and then show/save.
        """
        if not passphrase:
            self.show_error("Decrypt Failed", "Passphrase is required.")
            return

        self.statusBar().showMessage(f"Fetching and decrypting {item['id']}...")
        
        # --- ADDED: Disable the group box while processing ---
        # Find the group box to disable it
        item_widget = self.findChild(QGroupBox, f"item_group_{item['id']}")
        if item_widget:
            item_widget.setEnabled(False)
        # --- END ADD ---

        def decrypt_task(sess, item_id, pw, vk, task_mode):
            """This function runs in the worker thread."""
            # 1. Fetch
            pkg = api_recv64(sess, item_id)
            blob = base64.b64decode(pkg["b64"])
            
            # 2. Decrypt
            if task_mode == "text":
                env = json.loads(blob.decode("utf-8", "strict"))
                if "kdf" not in env or "salt_b64" not in env["kdf"]:
                    raise ValueError("Envelope missing KDF salt")
                salt = base64.b64decode(env["kdf"]["salt_b64"])
                dk = derive_key_from_password(pw, salt)
                clear_text = super_decrypt_text(env, vk, dk.key)
                return "text", clear_text
            
            elif task_mode == "file":
                pt_bytes = aesgcm_decrypt_bytes_with_passphrase(pw, blob)
                fname = pkg.get("filename") or f"{item_id}.bin"
                if fname.lower().endswith(".enc"):
                    fname = fname[:-4]
                return "file", (pt_bytes, fname) # Return (data, suggested_filename)
                
            elif task_mode == "stego":
                png_bytes = blob
                env = reveal_env_from_png_bytes(png_bytes)
                if "kdf" not in env or "salt_b64" not in env["kdf"]:
                    raise ValueError("Envelope missing KDF salt")
                salt = base64.b64decode(env["kdf"]["salt_b64"])
                dk = derive_key_from_password(pw, salt)
                clear_text = super_decrypt_text(env, vk, dk.key)
                return "stego", (clear_text, png_bytes)
            
            else:
                raise ValueError(f"Unknown decrypt mode: {task_mode}")
        
        # --- Start worker ---
        worker = Worker(decrypt_task, self.session, item["id"], passphrase, vkey, mode)
        worker.signals.success.connect(self.on_decrypt_item_success)
        # --- MODIFIED: Re-enable widget on error ---
        worker.signals.error.connect(
             lambda e: (
                self.show_error("Decrypt Failed", f"Could not decrypt {item['id']}: {e}"),
                item_widget.setEnabled(True) if item_widget else None
             )
        )
        # --- MODIFIED: Re-enable widget on finish (if not successful) ---
        worker.signals.finished.connect(
            lambda: (
                item_widget.setEnabled(True) if item_widget else None,
                self.on_worker_finished(worker)
            )
        )
        # --- END MOD ---

        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot(object)
    def on_download_raw_success(self, data: bytes, filename: str):
        """Shows a save dialog for raw downloaded data."""
        self.statusBar().showMessage("Download complete. Select save location.")
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Raw File", filename)
        
        if save_path:
            try:
                pathlib.Path(save_path).write_bytes(data)
                self.show_success("Saved", f"Raw file saved to {save_path}")
            except Exception as e:
                self.show_error("Save Failed", f"Could not save file: {e}")

    @Slot(object)
    def on_decrypt_item_success(self, result: tuple):
        """Handles the successful result from the decrypt worker."""
        # Note: Widget is re-enabled in the 'finished' signal
        mode, data = result
        
        self.statusBar().showMessage("Decryption successful.")
        
        if mode == "text":
            # Data is clear_text
            self.show_success("Decrypted Text", "Decryption successful.")
            # Show in a separate, scrollable message box
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle(f"Decrypted Text ({mode})")
            
            scroll_area = QScrollArea(msg_box)
            scroll_area.setWidgetResizable(True)
            scroll_area.setMinimumSize(400, 200)
            
            text_widget = QTextEdit(data)
            text_widget.setReadOnly(True)
            
            scroll_area.setWidget(text_widget)
            msg_box.layout().addWidget(scroll_area, 1, 0, 1, msg_box.layout().columnCount())
            msg_box.exec()

        elif mode == "stego":
            # Data is (clear_text, png_bytes)
            clear_text, png_bytes = data
            
            # Create a custom dialog to show both image and text
            dialog = QDialog(self)
            dialog.setWindowTitle("Decrypted Stego Message")
            dialog.setMinimumWidth(450)
            
            layout = QVBoxLayout(dialog)
            
            # Image Preview
            image_label = QLabel()
            pixmap = QPixmap()
            pixmap.loadFromData(png_bytes, "PNG")
            if not pixmap.isNull():
                image_label.setPixmap(
                    pixmap.scaled(
                        400, 300, 
                        Qt.AspectRatioMode.KeepAspectRatio, 
                        Qt.TransformationMode.SmoothTransformation
                    )
                )
            else:
                image_label.setText("Could not load PNG preview.")
            image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(image_label)
            
            # Decrypted Text
            layout.addWidget(QLabel("Decrypted Text:"))
            
            scroll_area = QScrollArea(dialog)
            scroll_area.setWidgetResizable(True)
            scroll_area.setMinimumHeight(150)
            
            text_widget = QTextEdit(clear_text)
            text_widget.setReadOnly(True)
            
            scroll_area.setWidget(text_widget)
            layout.addWidget(scroll_area)
            
            # OK Button
            ok_button = QPushButton("OK")
            ok_button.clicked.connect(dialog.accept)
            layout.addWidget(ok_button)
            
            dialog.exec()

        elif mode == "file":
            # Data is (pt_bytes, suggested_filename)
            pt_bytes, filename = data
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", filename)
            if save_path:
                try:
                    pathlib.Path(save_path).write_bytes(pt_bytes)
                    self.show_success("File Saved", f"Decrypted file saved to {save_path}")
                except Exception as e:
                    self.show_error("Save Failed", f"Could not save decrypted file: {e}")
        
        # --- MODIFIED: Refresh inbox after successful decrypt (if one-time) ---
        # A bit of a lazy way, but ensures the UI is consistent
        # A better way would be to check if the item was one-time
        self.do_refresh_inbox()
        # --- END MOD ---


# ---------------------------------
# --- APPLICATION ENTRY POINT ---
# ---------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Simple stylesheet
    app.setStyleSheet("""
        QWidget {
            font-family: Inter, sans-serif;
            font-size: 10pt;
        }
        QGroupBox {
            font-size: 11pt;
            font-weight: bold;
        }
        QPushButton {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 4px;
        }
        QPushButton:hover {
            background-color: #0056b3;
        }
        QPushButton:disabled {
            background-color: #cccccc;
        }
        QPushButton#refresh_inbox_button {
            background-color: #28a745;
        }
        QPushButton#refresh_inbox_button:hover {
            background-color: #218838;
        }
        
        /* --- ADDED: Style for the delete button --- */
        QPushButton#delete_button {
            background-color: #dc3545; /* A nice red */
        }
        QPushButton#delete_button:hover {
            background-color: #c82333; /* A darker red */
        }
        /* --- END ADD --- */

        QLineEdit, QTextEdit, QSpinBox {
            border: 1px solid #cccccc;
            border-radius: 4px;
            padding: 5px;
        }
        QStatusBar {
            background-color: #f8f9fa;
        }
    """)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())