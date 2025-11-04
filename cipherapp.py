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
import subprocess
import tempfile
import pathlib
import secrets
from dataclasses import dataclass
from typing import Optional, Callable
import traceback
import asyncio
import keyring
import ctypes
import ctypes

# for pyinstall
# Resolve paths both in normal Python and PyInstaller (_MEIPASS)
ROOT = pathlib.Path(__file__).resolve().parent
BASE = pathlib.Path(getattr(sys, "_MEIPASS", ROOT))   # <- bundle dir at runtime

# Make bundled packages importable (auth/, crypto/, stego/)
sys.path.insert(0, str(BASE))
# --- END OF ADDED CODE ---

# --- Qt Imports ---
from PySide6.QtCore import (
    QObject, Signal, Slot, QRunnable, QThreadPool, Qt, QStandardPaths, QTimer
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTabWidget, QLabel, QTextEdit, QSpinBox,
    QCheckBox, QFileDialog, QMessageBox, QStatusBar, QScrollArea,
    QGroupBox, QFrame, QGridLayout, QFormLayout, QDialog, QComboBox,
    QListWidget, QListWidgetItem
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

# --- HELPER MODE: run Windows Hello then exit with code ---
def _hello_helper_main() -> int:
    """
    Windowed helper path that ONLY runs Windows Hello and exits.
    Return codes: 0 = verified, 1 = denied/cancelled, 2 = unavailable/error.
    """
    try:
        # Import here so main app can still run without winrt installed.
        from winrt.windows.security.credentials.ui import (
            UserConsentVerifier, UserConsentVerifierAvailability, UserConsentVerificationResult
        )
    except Exception:
        return 2

    import asyncio

    async def go():
        avail = await UserConsentVerifier.check_availability_async()
        if avail != UserConsentVerifierAvailability.AVAILABLE:
            return 2
        res = await UserConsentVerifier.request_verification_async("Sign in to CipherDrop")
        return 0 if res == UserConsentVerificationResult.VERIFIED else 1

    try:
        try:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(go())
        except RuntimeError:
            # no loop yet
            return asyncio.run(go())
    except Exception:
        return 2

def _hello_available_main() -> int:
    """
    Exit 0 if Windows Hello is AVAILABLE, else 2.
    """
    try:
        from winrt.windows.security.credentials.ui import (
            UserConsentVerifier, UserConsentVerifierAvailability
        )
    except Exception:
        return 2

    import asyncio

    async def go():
        try:
            avail = await UserConsentVerifier.check_availability_async()
            return 0 if avail == UserConsentVerifierAvailability.AVAILABLE else 2
        except Exception:
            return 2

    try:
        try:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(go())
        except RuntimeError:
            return asyncio.run(go())
    except Exception:
        return 2

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
    # If login failed, raise an exception with the server-provided message
    if r.status_code != 200:
        # Try to extract a helpful error message from JSON body, fallback to text
        try:
            body = r.json()
            msg = body.get("detail") or body.get("message") or json.dumps(body)
        except Exception:
            msg = r.text or r.reason
        raise RuntimeError(f"Wrong username or password!")

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


# --- GROUP API FUNCTIONS ---
def api_create_group(sess: Session, name: str, encrypted_group_key_b64: str):
    """Create a new group."""
    r = requests.post(
        f"{sess.api}/api/groups/create",
        headers=sess.headers,
        json={"name": name, "encrypted_group_key_b64": encrypted_group_key_b64}
    )
    r.raise_for_status()
    return r.json()

def api_list_groups(sess: Session):
    """List all groups the user is a member of."""
    r = requests.get(f"{sess.api}/api/groups", headers=sess.headers)
    r.raise_for_status()
    return r.json()

def api_get_group_members(sess: Session, group_id: str):
    """Get all members of a group."""
    r = requests.get(f"{sess.api}/api/groups/{group_id}/members", headers=sess.headers)
    r.raise_for_status()
    return r.json()

def api_add_group_member(sess: Session, group_id: str, username: str, encrypted_group_key_b64: str):
    """Add a member to a group."""
    r = requests.post(
        f"{sess.api}/api/groups/{group_id}/members",
        headers=sess.headers,
        json={"username": username, "encrypted_group_key_b64": encrypted_group_key_b64}
    )
    r.raise_for_status()
    return r.json()

def api_remove_group_member(sess: Session, group_id: str, username: str):
    """Remove a member from a group."""
    r = requests.delete(
        f"{sess.api}/api/groups/{group_id}/members/{username}",
        headers=sess.headers
    )
    r.raise_for_status()
    return r.json()

def api_send_group_message(sess: Session, group_id: str, encrypted_blob_b64: str):
    """Send a message to a group."""
    r = requests.post(
        f"{sess.api}/api/groups/{group_id}/messages",
        headers=sess.headers,
        json={"encrypted_blob_b64": encrypted_blob_b64}
    )
    r.raise_for_status()
    return r.json()

def api_get_group_messages(sess: Session, group_id: str, limit: int = 50):
    """Get messages from a group."""
    r = requests.get(
        f"{sess.api}/api/groups/{group_id}/messages",
        headers=sess.headers,
        params={"limit": limit}
    )
    r.raise_for_status()
    return r.json()

def api_delete_group(sess: Session, group_id: str):
    """Delete a group."""
    r = requests.delete(f"{sess.api}/api/groups/{group_id}", headers=sess.headers)
    r.raise_for_status()
    return r.json()
# --- END GROUP API FUNCTIONS ---


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

# --- GROUP KEY MANAGEMENT HELPERS ---
def generate_group_key() -> bytes:
    """Generate a random 32-byte group key for AES-256."""
    return secrets.token_bytes(32)

def encrypt_group_key_for_user(group_key: bytes, user_passphrase: str) -> str:
    """
    Encrypt a group key with a user's passphrase.
    Returns base64-encoded encrypted envelope.
    """
    # Use the existing crypto to encrypt the group key
    dk = derive_key_from_password(user_passphrase)
    
    # Treat the group key as "text" to encrypt
    group_key_hex = group_key.hex()
    env = super_encrypt_text(group_key_hex, "GROUPKEY", dk.key)
    
    # Add KDF info
    env["kdf"] = {
        "type": "argon2id",
        "salt_b64": base64.b64encode(dk.salt).decode(),
        "t": ARGON_PARAMS["time_cost"],
        "m": ARGON_PARAMS["memory_cost"],
        "p": ARGON_PARAMS["parallelism"],
    }
    
    # Return as base64-encoded JSON
    return base64.b64encode(json.dumps(env).encode()).decode()

def decrypt_group_key_for_user(encrypted_group_key_b64: str, user_passphrase: str) -> bytes:
    """
    Decrypt a group key using a user's passphrase.
    Returns the raw group key bytes.
    """
    # Decode the base64 envelope
    env = json.loads(base64.b64decode(encrypted_group_key_b64))
    
    # Derive key from passphrase
    salt = base64.b64decode(env["kdf"]["salt_b64"])
    dk = derive_key_from_password(user_passphrase, salt)
    
    # Decrypt
    group_key_hex = super_decrypt_text(env, "GROUPKEY", dk.key)
    return bytes.fromhex(group_key_hex)

def encrypt_group_message(message: str, group_key: bytes) -> str:
    """
    Encrypt a message with a group key.
    Returns base64-encoded encrypted blob.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    aesgcm = AESGCM(group_key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    
    # Package nonce + ciphertext
    blob = nonce + ciphertext
    return base64.b64encode(blob).decode()

def decrypt_group_message(encrypted_blob_b64: str, group_key: bytes) -> str:
    """
    Decrypt a message with a group key.
    Returns the plain text message.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    blob = base64.b64decode(encrypted_blob_b64)
    nonce = blob[:12]
    ciphertext = blob[12:]
    
    aesgcm = AESGCM(group_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')
# --- END GROUP KEY MANAGEMENT HELPERS ---

# ----------------------------------------------------------------------
# WINDOWS HELLO UTILITY FUNCTIONS
# ----------------------------------------------------------------------

def hello_is_available() -> bool:
    try:
        # In PyInstaller bundle, sys.executable is the exe; in script mode, use __file__
        if getattr(sys, '_MEIPASS', None):
            # Bundled mode: sys.executable is the exe
            rc = subprocess.run([sys.executable, "--hello-available"]).returncode
        else:
            # Script mode: need to pass script file
            rc = subprocess.run([sys.executable, __file__, "--hello-available"]).returncode
        return rc == 0
    except Exception:
        return False  # be conservative if anything fails

def run_hello_via_self_helper() -> bool:
    try:
        ctypes.windll.user32.AllowSetForegroundWindow(-1)
    except Exception:
        pass
    # In PyInstaller bundle, sys.executable is the exe; in script mode, use __file__
    if getattr(sys, '_MEIPASS', None):
        # Bundled mode: sys.executable is the exe
        rc = subprocess.run([sys.executable, "--hello-helper"]).returncode
    else:
        # Script mode: need to pass script file
        rc = subprocess.run([sys.executable, __file__, "--hello-helper"]).returncode
    return rc == 0

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

    def _get_contacts_file(self) -> pathlib.Path:
        """Returns the path to the contacts file for the current user."""
        if not self.session.username:
            return CONFIG_DIR / "contacts.json"
        return CONFIG_DIR / f"contacts_{self.session.username}.json"

    def _load_contacts(self) -> list:
        """Loads contacts list for the current user."""
        contacts_file = self._get_contacts_file()
        try:
            if contacts_file.exists():
                contacts_data = json.loads(contacts_file.read_text())
                return contacts_data.get("contacts", [])
        except Exception as e:
            print(f"Error reading contacts file: {e}")
        return []

    def _save_contacts(self, contacts: list):
        """Saves contacts list for the current user."""
        contacts_file = self._get_contacts_file()
        try:
            contacts_file.write_text(json.dumps({"contacts": contacts}, indent=2))
        except Exception as e:
            print(f"Error writing contacts file: {e}")

    def _add_contact(self, username: str) -> bool:
        """Adds a contact to the list. Returns True if added, False if already exists."""
        contacts = self._load_contacts()
        username_clean = username.strip()
        if not username_clean:
            return False
        if username_clean not in contacts:
            contacts.append(username_clean)
            self._save_contacts(contacts)
            return True
        return False

    def _remove_contact(self, username: str):
        """Removes a contact from the list."""
        contacts = self._load_contacts()
        if username in contacts:
            contacts.remove(username)
            self._save_contacts(contacts)

    def _refresh_contacts_ui(self):
        """Refreshes all contact-related UI elements with current contacts."""
        contacts = self._load_contacts()
        
        # Update all comboboxes
        for combo in [self.send_to_user_edit, self.file_to_user_edit, self.stego_to_user_edit]:
            if isinstance(combo, QComboBox):
                current_text = combo.currentText()
                combo.clear()
                combo.setEditable(True)
                combo.addItem("")  # Empty option
                combo.addItems(contacts)
                # Restore current text if it was a contact
                if current_text in contacts:
                    combo.setCurrentText(current_text)
                else:
                    combo.setEditText(current_text)
        
        # Update contacts list widget
        if hasattr(self, 'contacts_list_widget'):
            self.contacts_list_widget.clear()
            for contact in contacts:
                self.contacts_list_widget.addItem(contact)

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
        
        self.passphrase_cache = {}
        self.vkey_cache = {}
        
        # --- Group State ---
        self.groups_list = []  # List of group dicts
        self.current_group_id = None  # Currently selected group
        self.group_keys_cache = {}  # {group_id: decrypted_group_key_bytes}
        
        self.inbox_refresh_timer = QTimer(self)
        self.inbox_refresh_timer.setInterval(5000)
        self.inbox_refresh_timer.timeout.connect(self.do_refresh_inbox)
        
        # --- Store file paths for uploads ---
        self.send_file_path = None
        self.stego_cover_png_path = None
        self.stego_local_png_path = None

        # --- Contacts storage ---
        self.contacts_list = []

        # --- Init UI ---
        self.init_ui()
        self.update_ui_for_login_status()
        # Kill auto-prompt on startup (just in case) - only the button triggers Hello
        # self.try_biometric_login()

    def on_biometrics_toggle(self, state: int):
        """Handle the biometrics checkbox state change."""
        if not self.session.username:  # Safety check
            return
        
        enable = state == Qt.CheckState.Checked.value

        if enable and not hello_is_available():
            self.show_error("Windows Hello", "Windows Hello isn't available on this device/account.")
            # flip the checkbox back off
            self.biometrics_toggle_check.setChecked(False)
            return
            
        config = self._read_app_config()
        is_enabled = enable
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
                if run_hello_via_self_helper():
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
        
        
        # NEW: Windows Hello button (manual trigger)
        self.hello_button = QPushButton("Unlock with Windows Hello")
        # Enable based on both config and availability
        biometrics_enabled = config.get("biometrics_enabled", False)
        self.hello_button.setEnabled(biometrics_enabled and hello_is_available())
        login_layout.addWidget(self.hello_button)
        
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
        self.biometrics_toggle_check = QCheckBox("Enable Biometric Login")
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
        
        # NEW:
        self.hello_button.clicked.connect(self.do_bio_login_clicked)

        return sidebar_frame

    def create_main_tabs(self) -> QTabWidget:
        """Creates the main QTabWidget for app functionality."""
        tabs = QTabWidget()
        tabs.addTab(self.create_inbox_tab(), "Inbox")
        tabs.addTab(self.create_compose_tab(), "Compose")
        tabs.addTab(self.create_groups_tab(), "Groups")
        tabs.addTab(self.create_stego_decrypt_tab(), "Local Decrypt")
        tabs.addTab(self.create_contacts_tab(), "Contacts")
        
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
        self.file_to_user_edit = QLineEdit()  # Allow typing new usernames
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

    def create_groups_tab(self) -> QWidget:
        """Creates the Groups tab with sub-tabs for management and chat."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create sub-tabs for groups
        groups_tabs = QTabWidget()
        groups_tabs.addTab(self.create_group_list_tab(), "My Groups")
        groups_tabs.addTab(self.create_group_create_tab(), "Create Group")
        groups_tabs.addTab(self.create_group_chat_tab(), "Group Chat")
        
        layout.addWidget(groups_tabs)
        return widget

    def create_group_list_tab(self) -> QWidget:
        """Creates the group list and management tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        header_layout = QHBoxLayout()
        header = QLabel("My Groups")
        header.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        header_layout.addWidget(header)
        header_layout.addStretch()
        
        self.refresh_groups_button = QPushButton("Refresh Groups")
        self.refresh_groups_button.clicked.connect(self.do_refresh_groups)
        header_layout.addWidget(self.refresh_groups_button)
        
        layout.addLayout(header_layout)
        
        # --- Groups List ---
        self.groups_list_widget = QListWidget()
        self.groups_list_widget.itemClicked.connect(self.on_group_selected)
        layout.addWidget(self.groups_list_widget, 1)
        
        # --- Group Actions ---
        actions_layout = QHBoxLayout()
        self.view_group_button = QPushButton("View Members")
        self.view_group_button.clicked.connect(self.do_view_group_members)
        self.delete_group_button = QPushButton("Delete Group")
        self.delete_group_button.clicked.connect(self.do_delete_group)
        self.leave_group_button = QPushButton("Leave Group")
        self.leave_group_button.clicked.connect(self.do_leave_group)
        
        actions_layout.addWidget(self.view_group_button)
        actions_layout.addWidget(self.delete_group_button)
        actions_layout.addWidget(self.leave_group_button)
        layout.addLayout(actions_layout)
        
        layout.addStretch()
        return widget

    def create_group_create_tab(self) -> QWidget:
        """Creates the group creation tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        header = QLabel("Create New Group")
        header.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # --- Form ---
        form_layout = QFormLayout()
        self.group_name_edit = QLineEdit(placeholderText="Enter group name...")
        self.group_passphrase_edit = QLineEdit(echoMode=QLineEdit.Password, placeholderText="Your passphrase for encryption...")
        
        form_layout.addRow("Group Name:", self.group_name_edit)
        form_layout.addRow("Your Passphrase:", self.group_passphrase_edit)
        layout.addLayout(form_layout)
        
        info_label = QLabel("ℹ️ A random group key will be generated and encrypted with your passphrase.\nYou'll need this passphrase to decrypt group messages.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(info_label)
        
        # --- Create Button ---
        self.create_group_button = QPushButton("Create Group")
        self.create_group_button.clicked.connect(self.do_create_group)
        layout.addWidget(self.create_group_button)
        
        # --- Add Members Section ---
        add_member_group = QGroupBox("Add Members to New Group")
        add_member_layout = QVBoxLayout()
        
        add_form = QHBoxLayout()
        self.add_member_username_edit = QLineEdit(placeholderText="Username to add...")
        self.add_member_passphrase_edit = QLineEdit(echoMode=QLineEdit.Password, placeholderText="Their passphrase...")
        self.add_member_button = QPushButton("Add Member")
        self.add_member_button.clicked.connect(self.do_add_group_member)
        
        add_form.addWidget(QLabel("Username:"))
        add_form.addWidget(self.add_member_username_edit)
        add_form.addWidget(QLabel("Passphrase:"))
        add_form.addWidget(self.add_member_passphrase_edit)
        add_form.addWidget(self.add_member_button)
        
        add_member_layout.addLayout(add_form)
        
        info_label2 = QLabel("ℹ️ To add a member, you need their passphrase to encrypt the group key for them.\nIn practice, they would share their passphrase with you via a secure channel.")
        info_label2.setWordWrap(True)
        info_label2.setStyleSheet("color: #666; font-style: italic; font-size: 11px;")
        add_member_layout.addWidget(info_label2)
        
        add_member_group.setLayout(add_member_layout)
        layout.addWidget(add_member_group)
        
        layout.addStretch()
        return widget

    def create_group_chat_tab(self) -> QWidget:
        """Creates the group chat interface."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # --- Header with Group Selector ---
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("Group:"))
        
        self.chat_group_combo = QComboBox()
        self.chat_group_combo.currentIndexChanged.connect(self.on_chat_group_changed)
        header_layout.addWidget(self.chat_group_combo, 1)
        
        self.chat_passphrase_edit = QLineEdit(echoMode=QLineEdit.Password, placeholderText="Your passphrase...")
        header_layout.addWidget(QLabel("Passphrase:"))
        header_layout.addWidget(self.chat_passphrase_edit)
        
        self.unlock_chat_button = QPushButton("Unlock Chat")
        self.unlock_chat_button.clicked.connect(self.do_unlock_group_chat)
        header_layout.addWidget(self.unlock_chat_button)
        
        self.refresh_messages_button = QPushButton("Refresh")
        self.refresh_messages_button.clicked.connect(self.do_refresh_group_messages)
        header_layout.addWidget(self.refresh_messages_button)
        
        layout.addLayout(header_layout)
        
        # --- Messages Area ---
        self.group_messages_text = QTextEdit()
        self.group_messages_text.setReadOnly(True)
        self.group_messages_text.setMinimumHeight(300)
        layout.addWidget(self.group_messages_text, 1)
        
        # --- Send Message ---
        send_layout = QHBoxLayout()
        self.group_message_edit = QLineEdit(placeholderText="Type your message...")
        self.group_message_edit.returnPressed.connect(self.do_send_group_message)
        self.send_group_message_button = QPushButton("Send")
        self.send_group_message_button.clicked.connect(self.do_send_group_message)
        
        send_layout.addWidget(self.group_message_edit, 1)
        send_layout.addWidget(self.send_group_message_button)
        layout.addLayout(send_layout)
        
        # Initially locked
        self.group_message_edit.setEnabled(False)
        self.send_group_message_button.setEnabled(False)
        self.refresh_messages_button.setEnabled(False)
        
        return widget

    def create_contacts_tab(self) -> QWidget:
        """Creates the Contacts management tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        header = QLabel("Manage Contacts")
        header.setFont(QFont("Inter", 16, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # NEW: Use-in-Compose button
        self.use_contact_button = QPushButton("Use Selected in Compose…")
        self.use_contact_button.clicked.connect(self.do_use_contact_in_compose)
        
        # --- Add Contact Section ---
        add_contact_group = QGroupBox("Add Contact")
        add_contact_layout = QHBoxLayout()
        self.add_contact_edit = QLineEdit(placeholderText="Enter username...")
        self.add_contact_button = QPushButton("Add Contact")
        self.add_contact_button.clicked.connect(self.do_add_contact)
        add_contact_layout.addWidget(self.add_contact_edit)
        add_contact_layout.addWidget(self.add_contact_button)
        add_contact_group.setLayout(add_contact_layout)
        layout.addWidget(add_contact_group)
        
        # --- Contacts List ---
        contacts_list_group = QGroupBox("Your Contacts")
        contacts_list_layout = QVBoxLayout()
        self.contacts_list_widget = QListWidget()
        self.remove_contact_button = QPushButton("Remove Selected Contact")
        self.remove_contact_button.clicked.connect(self.do_remove_contact)
        contacts_list_layout.addWidget(self.contacts_list_widget)
        contacts_list_layout.addWidget(self.use_contact_button)   
        contacts_list_layout.addWidget(self.remove_contact_button)
        contacts_list_group.setLayout(contacts_list_layout)
        layout.addWidget(contacts_list_group, 1)  # Stretch factor
        
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
            
            # Load and refresh contacts UI
            self._refresh_contacts_ui()
            
            self.statusBar().showMessage("Ready.")
            # Auto-refresh inbox on login
            self.do_refresh_inbox()
        else:
            self.statusBar().showMessage("Please log in.")
            # Clear inbox
            self.clear_inbox_layout()
            self.inbox_layout.addWidget(QLabel("Please log in to see your inbox."))
            # Clear contacts UI
            if hasattr(self, 'contacts_list_widget'):
                self.contacts_list_widget.clear()
            for combo_name in ['send_to_user_edit', 'file_to_user_edit', 'stego_to_user_edit']:
                if hasattr(self, combo_name):
                    combo = getattr(self, combo_name)

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
            
            ## Delete the stored token if it exists
            #try:
            #    keyring.delete_password("CipherDrop", self.session.username)
            #    print(f"Logged out. Removed token for {self.session.username}.")
            #except keyring.errors.NoKeyringError:
            #    print("No keyring service found to delete from.")
            #except keyring.errors.PasswordDeleteError:
            #    print(f"No token found for {self.session.username} to delete, or delete failed.")
            #except Exception as e:
            #    print(f"Error deleting token from keyring on logout: {e}")

        self.inbox_refresh_timer.stop()
        self.session.token = None
        self.session.username = None
        self.update_ui_for_login_status()
        self.statusBar().showMessage("Logged out.")
        
    @Slot()
    def do_bio_login_clicked(self):
        if not hello_is_available():
            self.show_error("Windows Hello", "Windows Hello isn't available.")
            return
        # Use a background worker so the blocking subprocess.run() call
        # doesn't freeze the main UI thread while Windows Hello prompt is shown.
        self.statusBar().showMessage("Waiting for Windows Hello…")
        # Disable the button while the prompt is active
        try:
            self.hello_button.setEnabled(False)
        except Exception:
            pass

        worker = Worker(run_hello_via_self_helper)
        # success will emit the boolean result from the helper
        worker.signals.success.connect(self.on_bio_login_success)
        worker.signals.error.connect(self.on_bio_login_error)
        # Ensure we remove the worker reference and re-enable UI when finished
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.hello_button.setEnabled(True))

        self.running_workers.add(worker)
        self.threadpool.start(worker)


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
    def do_use_contact_in_compose(self):
        """Confirm and auto-fill recipient fields in Compose from selected contact."""
        current_item = self.contacts_list_widget.currentItem() if hasattr(self, 'contacts_list_widget') else None
        if not current_item:
            self.show_error("Use in Compose", "Please select a contact first.")
            return
    
        username = current_item.text().strip()
        if not username:
            self.show_error("Use in Compose", "Selected contact is empty.")
            return
    
        # Confirm
        reply = QMessageBox.question(
            self,
            "Use in Compose",
            f"Use \"{username}\" as the recipient in Compose?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
    
        # Fill all Compose recipient fields (supports QLineEdit or legacy QComboBox)
        for field in [self.send_to_user_edit, self.file_to_user_edit, self.stego_to_user_edit]:
            if isinstance(field, QLineEdit):
                field.setText(username)
            elif isinstance(field, QComboBox):
                idx = field.findText(username, Qt.MatchFlag.MatchExactly)
                field.setCurrentIndex(idx if idx >= 0 else field.currentIndex())
                if idx < 0:
                    field.setEditText(username)
    
        # Jump to Compose tab
        if isinstance(self.main_tabs, QTabWidget):
            self.main_tabs.setCurrentIndex(1)
    
        self.statusBar().showMessage(f"Recipient set to {username} in Compose.")


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
        
    @Slot(str, str)
    def on_inbox_passphrase_changed(self, item_id: str, text: str):
        """Saves the text from an inbox passphrase field to cache."""
        self.passphrase_cache[item_id] = text

    @Slot(str, str)
    def on_inbox_vkey_changed(self, item_id: str, text: str):
        """Saves the text from an inbox vigenere key field to cache."""
        self.vkey_cache[item_id] = text

    @Slot()
    def do_send_text(self):
        """Validates form and starts the send_text worker."""
        to_user = (
        self.send_to_user_edit.text()
        if hasattr(self, "send_to_user_edit")
        else ""
        )
        passphrase = self.send_passphrase_edit.text()
        message = self.send_message_text.toPlainText()
        vkey = self.send_vkey_edit.text()
        ttl = self.send_ttl_spinbox.value()
        one_time = self.send_onetime_check.isChecked()

        if not to_user or not passphrase or not message:
            self.show_error("Send Failed", "Recipient, passphrase, and message are required.")
            return
        
        # Auto-add recipient to contacts
        if to_user.strip():
            self._add_contact(to_user.strip())
            self._refresh_contacts_ui()

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

        # --- THIS IS THE ANTI-STACKING CHECK ---
        # If the button is *already* disabled, it means a refresh
        # is in progress. Don't start another one.
        if not self.refresh_inbox_button.isEnabled():
            return
        # --- END OF CHECK ---

        self.statusBar().showMessage("Refreshing inbox...")
        self.refresh_inbox_button.setEnabled(False)

        worker = Worker(api_inbox, self.session)
        worker.signals.success.connect(self.on_inbox_success)
        worker.signals.error.connect(self.on_inbox_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))

        # This is the line you wanted to retain, which is perfect.
        # It re-enables the button when the worker is done.
        worker.signals.finished.connect(lambda: self.refresh_inbox_button.setEnabled(True))

        self.running_workers.add(worker) # Hold reference
        self.threadpool.start(worker)

    @Slot()
    def do_send_file(self):
        """Validates and starts the send_file worker."""
        to_user = self.file_to_user_edit.currentText() if isinstance(self.file_to_user_edit, QComboBox) else self.file_to_user_edit.text()
        passphrase = self.file_passphrase_edit.text()
        file_path = self.send_file_path
        
        if not to_user or not passphrase or not file_path:
            self.show_error("Send Failed", "Recipient, passphrase, and a selected file are required.")
            return
        
        # Auto-add recipient to contacts
        if to_user.strip():
            self._add_contact(to_user.strip())
            self._refresh_contacts_ui()

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
        to_user = self.stego_to_user_edit.currentText() if isinstance(self.stego_to_user_edit, QComboBox) else self.stego_to_user_edit.text()
        passphrase = self.stego_passphrase_edit.text()
        vkey = self.stego_vkey_edit.text()
        message = self.stego_message_text.toPlainText()
        cover_path = self.stego_cover_png_path
        
        if not (to_user and passphrase and vkey and message and cover_path):
            self.show_error("Send Failed", "All fields and a cover PNG are required.")
            return
        
        # Auto-add recipient to contacts
        if to_user.strip():
            self._add_contact(to_user.strip())
            self._refresh_contacts_ui()

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

    @Slot()
    def do_add_contact(self):
        """Adds a contact from the input field."""
        username = self.add_contact_edit.text().strip()
        if not username:
            self.show_error("Add Contact", "Please enter a username.")
            return
        
        if self._add_contact(username):
            self.show_success("Contact Added", f"Added {username} to your contacts.")
            self.add_contact_edit.clear()
            self._refresh_contacts_ui()
        else:
            self.show_error("Add Contact", f"{username} is already in your contacts.")

    @Slot()
    def do_remove_contact(self):
        """Removes the selected contact from the list."""
        current_item = self.contacts_list_widget.currentItem()
        if not current_item:
            self.show_error("Remove Contact", "Please select a contact to remove.")
            return
        
        username = current_item.text()
        self._remove_contact(username)
        self.show_success("Contact Removed", f"Removed {username} from your contacts.")
        self._refresh_contacts_ui()

    # --- GROUP OPERATIONS ---

    @Slot()
    def do_refresh_groups(self):
        """Refreshes the list of groups."""
        if not self.refresh_groups_button.isEnabled():
            return
        
        self.statusBar().showMessage("Refreshing groups...")
        self.refresh_groups_button.setEnabled(False)
        
        worker = Worker(api_list_groups, self.session)
        worker.signals.success.connect(self.on_refresh_groups_success)
        worker.signals.error.connect(self.on_refresh_groups_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.refresh_groups_button.setEnabled(True))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    @Slot()
    def do_create_group(self):
        """Creates a new group with an encrypted group key."""
        name = self.group_name_edit.text().strip()
        passphrase = self.group_passphrase_edit.text()
        
        if not name or not passphrase:
            self.show_error("Create Group", "Group name and passphrase are required.")
            return
        
        self.statusBar().showMessage("Creating group...")
        self.create_group_button.setEnabled(False)
        
        def create_task(sess, name, passphrase):
            # Generate group key
            group_key = generate_group_key()
            
            # Encrypt it for the creator
            encrypted_key_b64 = encrypt_group_key_for_user(group_key, passphrase)
            
            # Create the group
            result = api_create_group(sess, name, encrypted_key_b64)
            return result, group_key  # Return both for caching
        
        worker = Worker(create_task, self.session, name, passphrase)
        worker.signals.success.connect(self.on_create_group_success)
        worker.signals.error.connect(self.on_create_group_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.create_group_button.setEnabled(True))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    @Slot()
    def do_add_group_member(self):
        """Adds a member to the currently selected group."""
        if not self.current_group_id:
            self.show_error("Add Member", "Please select a group from 'My Groups' first.")
            return
        
        username = self.add_member_username_edit.text().strip()
        passphrase = self.add_member_passphrase_edit.text()
        
        if not username or not passphrase:
            self.show_error("Add Member", "Username and passphrase are required.")
            return
        
        # Get the group key from cache
        if self.current_group_id not in self.group_keys_cache:
            self.show_error("Add Member", "Group key not available. Please unlock the group first in 'Group Chat'.")
            return
        
        group_key = self.group_keys_cache[self.current_group_id]
        
        self.statusBar().showMessage(f"Adding {username} to group...")
        self.add_member_button.setEnabled(False)
        
        def add_task(sess, group_id, username, group_key, passphrase):
            # Encrypt the group key for the new member
            encrypted_key_b64 = encrypt_group_key_for_user(group_key, passphrase)
            return api_add_group_member(sess, group_id, username, encrypted_key_b64)
        
        worker = Worker(add_task, self.session, self.current_group_id, username, group_key, passphrase)
        worker.signals.success.connect(self.on_add_member_success)
        worker.signals.error.connect(self.on_add_member_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.add_member_button.setEnabled(True))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    @Slot()
    def on_group_selected(self, item):
        """Called when a group is selected in the list."""
        if not item:
            return
        # Extract group ID from item data
        group_id = item.data(Qt.ItemDataRole.UserRole)
        self.current_group_id = group_id

    @Slot()
    def do_view_group_members(self):
        """Views members of the currently selected group."""
        if not self.current_group_id:
            self.show_error("View Members", "Please select a group first.")
            return
        
        self.statusBar().showMessage("Loading group members...")
        
        worker = Worker(api_get_group_members, self.session, self.current_group_id)
        worker.signals.success.connect(self.on_view_members_success)
        worker.signals.error.connect(self.on_view_members_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    @Slot()
    def do_delete_group(self):
        """Deletes the currently selected group (creator only)."""
        if not self.current_group_id:
            self.show_error("Delete Group", "Please select a group first.")
            return
        
        reply = QMessageBox.warning(
            self,
            "Confirm Delete",
            "Are you sure you want to delete this group? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.statusBar().showMessage("Deleting group...")
        
        worker = Worker(api_delete_group, self.session, self.current_group_id)
        worker.signals.success.connect(self.on_delete_group_success)
        worker.signals.error.connect(self.on_delete_group_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    @Slot()
    def do_leave_group(self):
        """Leaves the currently selected group."""
        if not self.current_group_id:
            self.show_error("Leave Group", "Please select a group first.")
            return
        
        reply = QMessageBox.warning(
            self,
            "Confirm Leave",
            "Are you sure you want to leave this group?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        self.statusBar().showMessage("Leaving group...")
        
        worker = Worker(api_remove_group_member, self.session, self.current_group_id, self.session.username)
        worker.signals.success.connect(self.on_leave_group_success)
        worker.signals.error.connect(self.on_leave_group_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    @Slot()
    def on_chat_group_changed(self):
        """Called when the chat group selector changes."""
        # Reset chat state when switching groups
        self.group_message_edit.setEnabled(False)
        self.send_group_message_button.setEnabled(False)
        self.refresh_messages_button.setEnabled(False)
        self.group_messages_text.clear()

    @Slot()
    def do_unlock_group_chat(self):
        """Unlocks a group chat by decrypting the group key."""
        group_index = self.chat_group_combo.currentIndex()
        if group_index < 0:
            self.show_error("Unlock Chat", "Please select a group first.")
            return
        
        group_id = self.chat_group_combo.itemData(group_index)
        passphrase = self.chat_passphrase_edit.text()
        
        if not passphrase:
            self.show_error("Unlock Chat", "Passphrase is required.")
            return
        
        # Find the group in the list to get the encrypted key
        group_info = None
        for g in self.groups_list:
            if g['id'] == group_id:
                group_info = g
                break
        
        if not group_info:
            self.show_error("Unlock Chat", "Group not found.")
            return
        
        self.statusBar().showMessage("Unlocking chat...")
        
        def unlock_task(encrypted_key_b64, passphrase):
            return decrypt_group_key_for_user(encrypted_key_b64, passphrase)
        
        worker = Worker(unlock_task, group_info['encrypted_group_key_b64'], passphrase)
        worker.signals.success.connect(lambda key: self.on_unlock_chat_success(group_id, key))
        worker.signals.error.connect(self.on_unlock_chat_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    @Slot()
    def do_refresh_group_messages(self):
        """Refreshes messages for the currently unlocked group."""
        group_index = self.chat_group_combo.currentIndex()
        if group_index < 0:
            return
        
        group_id = self.chat_group_combo.itemData(group_index)
        
        if group_id not in self.group_keys_cache:
            self.show_error("Refresh Messages", "Please unlock the chat first.")
            return
        
        self.statusBar().showMessage("Loading messages...")
        
        worker = Worker(api_get_group_messages, self.session, group_id)
        worker.signals.success.connect(lambda msgs: self.on_refresh_messages_success(group_id, msgs))
        worker.signals.error.connect(self.on_refresh_messages_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    @Slot()
    def do_send_group_message(self):
        """Sends a message to the group."""
        message = self.group_message_edit.text().strip()
        if not message:
            return
        
        group_index = self.chat_group_combo.currentIndex()
        if group_index < 0:
            return
        
        group_id = self.chat_group_combo.itemData(group_index)
        
        if group_id not in self.group_keys_cache:
            self.show_error("Send Message", "Please unlock the chat first.")
            return
        
        group_key = self.group_keys_cache[group_id]
        
        self.statusBar().showMessage("Sending message...")
        self.send_group_message_button.setEnabled(False)
        
        def send_task(sess, group_id, message, group_key):
            encrypted_blob_b64 = encrypt_group_message(message, group_key)
            return api_send_group_message(sess, group_id, encrypted_blob_b64)
        
        worker = Worker(send_task, self.session, group_id, message, group_key)
        worker.signals.success.connect(lambda r: self.on_send_message_success(group_id))
        worker.signals.error.connect(self.on_send_message_error)
        worker.signals.finished.connect(lambda: self.on_worker_finished(worker))
        worker.signals.finished.connect(lambda: self.send_group_message_button.setEnabled(True))
        self.running_workers.add(worker)
        self.threadpool.start(worker)

    # --- END GROUP OPERATIONS ---


    # -----------------------------------------------
    # --- "ON" METHODS (Worker -> GUI Callbacks) ---
    # -----------------------------------------------

    @Slot(object, str)
    def on_login_success(self, token, username):
        self.session.token = token
        self.session.username = username

        # Handle biometric settings
        config = self._read_app_config()  # Get existing config
        config["last_user"] = username
        
        # --- START OF FIX ---
        # Read the SAVED preference, not the UI checkbox state
        is_bio_enabled = config.get("biometrics_enabled", False)

        if is_bio_enabled:
            # Biometrics are enabled, so save the new token we just got
            try:
                keyring.set_password("CipherDrop", username, token)
                print(f"Token (re)saved to keyring for {username}")
            except Exception as e:
                print(f"WARNING: Could not save token to keyring: {e}")
                # Don't disable biometrics on failure, just warn.
        else:
            # Biometrics are not enabled, so make sure no old token is present
            try:
                keyring.delete_password("CipherDrop", username)
                print(f"Biometrics disabled. Ensured token for {username} is removed.")
            except (keyring.errors.NoKeyringError, keyring.errors.PasswordDeleteError):
                pass  # It's fine if it's already gone
            except Exception as e:
                print(f"Error clearing old token from keyring: {e}")

        # We ONLY write the last_user here. We DO NOT change the
        # biometrics_enabled flag, as only the user toggle should do that.
        self._write_app_config(config)
        
        # --- END OF FIX ---
        
        # This function will now read the (correct, unmodified) config
        # and set the checkbox state properly.
        self.update_ui_for_login_status()
        self.statusBar().showMessage("Logged in successfully.")
        self.inbox_refresh_timer.start()


    @Slot(Exception)
    def on_login_error(self, e):
        # self.login_button.setEnabled(True) # Handled by 'finished' signal
        self.show_error("Login Error", f"Could not log in: {e}")

    @Slot(object)
    def on_bio_login_success(self, ok: bool):
        """Handle successful return from the Windows Hello helper worker.
        `ok` is True when verification succeeded.
        """
        try:
            if ok:
                # reload token for last_user and update UI
                config = self._read_app_config()
                username = self.session.username or config.get("last_user")
                if username:
                    token = keyring.get_password("CipherDrop", username)
                    if token:
                        self.session.username = username
                        self.session.token = token
                        self.update_ui_for_login_status()
                        self.statusBar().showMessage("Unlocked with Windows Hello.")
                        return
                self.show_error("Windows Hello", "No saved token for the last user.")
            else:
                self.show_error("Windows Hello", "Verification failed, cancelled, or unavailable.")
        except Exception as e:
            # Any unexpected error handling the result
            self.show_error("Windows Hello Error", f"An error occurred handling biometric result: {e}")

    @Slot(Exception)
    def on_bio_login_error(self, e: Exception):
        """Handle unexpected exceptions raised while running the helper."""
        self.show_error("Windows Hello Error", f"An unexpected error occurred: {e}")

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
        
        # Auto-add senders from inbox to contacts
        contacts_updated = False
        for item in inbox_list:
            sender = item.get('from_user', '').strip()
            if sender and sender != self.session.username:
                if self._add_contact(sender):
                    contacts_updated = True
        
        if contacts_updated:
            self._refresh_contacts_ui()
        
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

    # --- GROUP CALLBACKS ---
    
    @Slot(object)
    def on_refresh_groups_success(self, groups_data):
        """Updates the groups list UI."""
        self.groups_list = groups_data
        self.statusBar().showMessage(f"Loaded {len(groups_data)} groups.")
        
        # Update the list widget
        self.groups_list_widget.clear()
        for group in groups_data:
            item_text = f"{group['name']} (by {group['creator']})"
            if group['is_admin']:
                item_text += " [Admin]"
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, group['id'])
            self.groups_list_widget.addItem(item)
        
        # Update chat combo
        self.chat_group_combo.clear()
        for group in groups_data:
            self.chat_group_combo.addItem(group['name'], group['id'])

    @Slot(Exception)
    def on_refresh_groups_error(self, e):
        self.show_error("Refresh Groups Error", f"Could not load groups: {e}")

    @Slot(object)
    def on_create_group_success(self, result):
        """Called when group is successfully created."""
        group_data, group_key = result
        group_id = group_data['id']
        
        # Cache the group key
        self.group_keys_cache[group_id] = group_key
        self.current_group_id = group_id
        
        self.show_success("Group Created", f"Group '{group_data['name']}' created successfully.\nYou can now add members.")
        self.group_name_edit.clear()
        self.group_passphrase_edit.clear()
        
        # Refresh groups list
        self.do_refresh_groups()

    @Slot(Exception)
    def on_create_group_error(self, e):
        self.show_error("Create Group Error", f"Could not create group: {e}")

    @Slot(object)
    def on_add_member_success(self, result):
        """Called when member is successfully added."""
        self.show_success("Member Added", f"User '{result['username']}' added to the group.")
        self.add_member_username_edit.clear()
        self.add_member_passphrase_edit.clear()

    @Slot(Exception)
    def on_add_member_error(self, e):
        self.show_error("Add Member Error", f"Could not add member: {e}")

    @Slot(object)
    def on_view_members_success(self, members):
        """Shows a dialog with group members."""
        member_text = "Group Members:\n\n"
        for member in members:
            admin_tag = " [Admin]" if member['is_admin'] else ""
            member_text += f"• {member['username']}{admin_tag}\n"
        
        QMessageBox.information(self, "Group Members", member_text)
        self.statusBar().showMessage("Members loaded.")

    @Slot(Exception)
    def on_view_members_error(self, e):
        self.show_error("View Members Error", f"Could not load members: {e}")

    @Slot(object)
    def on_delete_group_success(self, result):
        """Called when group is deleted."""
        self.show_success("Group Deleted", "Group has been deleted.")
        self.current_group_id = None
        self.do_refresh_groups()

    @Slot(Exception)
    def on_delete_group_error(self, e):
        self.show_error("Delete Group Error", f"Could not delete group: {e}")

    @Slot(object)
    def on_leave_group_success(self, result):
        """Called when user leaves a group."""
        self.show_success("Left Group", "You have left the group.")
        self.current_group_id = None
        self.do_refresh_groups()

    @Slot(Exception)
    def on_leave_group_error(self, e):
        self.show_error("Leave Group Error", f"Could not leave group: {e}")

    @Slot(str, bytes)
    def on_unlock_chat_success(self, group_id, group_key):
        """Called when group chat is unlocked."""
        self.group_keys_cache[group_id] = group_key
        
        # Enable chat controls
        self.group_message_edit.setEnabled(True)
        self.send_group_message_button.setEnabled(True)
        self.refresh_messages_button.setEnabled(True)
        
        self.statusBar().showMessage("Chat unlocked. Loading messages...")
        
        # Auto-load messages
        self.do_refresh_group_messages()

    @Slot(Exception)
    def on_unlock_chat_error(self, e):
        self.show_error("Unlock Error", f"Could not unlock chat: {e}\n\nMake sure you're using the correct passphrase.")

    @Slot(str, list)
    def on_refresh_messages_success(self, group_id, messages):
        """Displays decrypted group messages."""
        if group_id not in self.group_keys_cache:
            return
        
        group_key = self.group_keys_cache[group_id]
        
        # Clear and populate messages
        self.group_messages_text.clear()
        
        if not messages:
            self.group_messages_text.append("No messages yet. Be the first to send one!")
            return
        
        for msg in messages:
            try:
                plaintext = decrypt_group_message(msg['encrypted_blob_b64'], group_key)
                timestamp = msg['created_at'][:19]  # Trim to readable format
                self.group_messages_text.append(f"[{timestamp}] {msg['sender']}: {plaintext}")
            except Exception as e:
                self.group_messages_text.append(f"[{msg['created_at'][:19]}] {msg['sender']}: [Decryption failed]")
        
        # Scroll to bottom
        self.group_messages_text.moveCursor(self.group_messages_text.textCursor().End)
        self.statusBar().showMessage(f"Loaded {len(messages)} messages.")

    @Slot(Exception)
    def on_refresh_messages_error(self, e):
        self.show_error("Load Messages Error", f"Could not load messages: {e}")

    @Slot(str)
    def on_send_message_success(self, group_id):
        """Called when message is sent."""
        self.group_message_edit.clear()
        self.statusBar().showMessage("Message sent.")
        
        # Auto-refresh to show the new message
        self.do_refresh_group_messages()

    @Slot(Exception)
    def on_send_message_error(self, e):
        self.show_error("Send Message Error", f"Could not send message: {e}")

    # --- END GROUP CALLBACKS ---


    # ---------------------------------
    # --- DYNAMIC WIDGET CREATION ---
    # ---------------------------------

    def create_inbox_item_widget(self, item: dict) -> QGroupBox:
        """Dynamically creates a QGroupBox for an inbox item."""
        
        item_id = item['id']
        title = f"From: {item['from_user']}  ·  {item['filename'] or item['mime']}  (id: {item_id})"
        group_box = QGroupBox(title)
        group_layout = QVBoxLayout(group_box)
        
        # --- Determine item type for icon ---
        is_text_env = (item.get("mime","").startswith("application/json")
                       or str(item.get("filename","")).lower().endswith(".json"))
        is_png = (item.get("mime","") == "image/png") or str(item.get("filename","")).lower().endswith(".png")
        
        # --- NEW ICON LOGIC ---
        icon_label = QLabel()
        icon_path = ""
        if is_text_env:
            icon_path = str(BASE / "icon/icon_text.png") 
        elif is_png:
            icon_path = str(BASE / "icon/icon_stego.png")
        else:
            icon_path = str(BASE / "icon/icon_file.png")

        pixmap = QPixmap(icon_path)
        if not pixmap.isNull():
            icon_label.setPixmap(pixmap.scaled(32, 32, Qt.AspectRatioMode.KeepAspectRatio))

        # Add the icon next to the title (or wherever you like!)
        # You might need a simple QHBoxLayout here to put the icon and title together
        # For now, we'll just add it at the top of the group.
        group_layout.addWidget(icon_label) 
        # --- END NEW LOGIC ---
        
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
        # --- START REPLACEMENT ---
        item_id = item['id'] # Make sure this line is present
        
        decrypt_form = QWidget()
        form_layout = QFormLayout(decrypt_form)
        form_layout.setContentsMargins(0,0,0,0)
        
        passphrase_edit = QLineEdit(echoMode=QLineEdit.Password)
        vkey_edit = QLineEdit()

        # Restore text from cache if it exists
        if item_id in self.passphrase_cache:
            passphrase_edit.setText(self.passphrase_cache[item_id])
        
        if item_id in self.vkey_cache:
            vkey_edit.setText(self.vkey_cache[item_id])
        else:
            vkey_edit.setText("CRYPTO") # Use default only if no cache

        # Connect signals to update cache as user types
        passphrase_edit.textChanged.connect(
            lambda text, item_id=item_id: self.on_inbox_passphrase_changed(item_id, text)
        )
        vkey_edit.textChanged.connect(
            lambda text, item_id=item_id: self.on_inbox_vkey_changed(item_id, text)
        )

        form_layout.addRow("Passphrase:", passphrase_edit)
        form_layout.addRow("Vigenère Key:", vkey_edit)
        # --- END REPLACEMENT ---
        
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
        # (is_text_env and is_png are already determined above for the icon)
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
    if "--hello-helper" in sys.argv:
        sys.exit(_hello_helper_main())

    if "--hello-available" in sys.argv:
        sys.exit(_hello_available_main())

    # normal GUI startup...
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