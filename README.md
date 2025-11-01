(Here is the complete `README.md` file, formatted to be copied directly to GitHub.)

-----

# 🔐 CipherDrop Desktop

CipherDrop is a standalone desktop application for Windows that provides end-to-end encrypted (E2EE) messaging, file sharing, and steganography.

All encryption and decryption happen **locally on your machine**. Your passphrases are never sent to any server, ensuring only you and your recipient can access your data.

## 🚀 How to Install (The Easy Way)

You can download the latest pre-built application from the **Releases** tab.

1.  Go to the [**Releases**](https://www.google.com/search?q=https://github.com/tedjasatedji/cipherdrop/releases) page of this repository.
2.  Under the latest release, click on `cipherapp.exe` to download it.
3.  Your browser or Windows might show a security warning because the app is not "signed." This is normal for open-source projects. You may need to click "More info" -\> "Run anyway."
4.  That's it\! It's a portable `.exe`, so you can place it anywhere and run it. No installation is needed.

-----

## ✨ Core Features

  * **E2EE Text Messaging:** Send secret text messages protected by a hybrid encryption scheme (Vigenère cipher + ChaCha20-Poly1305).
  * **E2EE File Sharing:** Securely share any file. Files are encrypted locally using **AES-256-GCM** before being uploaded.
  * **Image Steganography:** Hide your encrypted text messages directly inside a PNG image. Send the image, and the recipient can use the app to reveal the secret message.
  * **Ephemeral Messages:** All items can be set as **one-time read** (they are deleted after the first download) or given a **Time-to-Live (TTL)** for automatic deletion.
  * **Biometric Unlock:** Securely save your session and unlock the app with **Windows Hello** (fingerprint or facial recognition). This feature is toggleable in the sidebar.
  * **Strong Key Derivation:** Your passphrase is run through **Argon2id** (a modern, secure password-hashing algorithm) to create the 32-byte encryption key.
  * **Connect Anywhere:** The app is not locked to a single server. You can change the **API URL** in the sidebar to point to any compatible CipherDrop server, including one you host yourself.

-----

## 👨‍💻 For Developers: Building & Hosting

This section is for developers who want to build the app from the source code or host their own private server.

### 🛠️ Building the `.exe` from Source

You can bundle the standalone `cipherapp.exe` from source using PyInstaller.

1.  **Install Dependencies:**
    This project requires several libraries, including PySide6 for the UI, and special packages for the Windows integration.

    ```bash
    pip install -r requirements.txt
    pip install PySide6 keyring winrt-windows
    ```

2.  **Add PyInstaller Hints:**
    `keyring` and `winrt-windows` require hints for PyInstaller to find all their hidden files. Add the following to the top of `cipherapp.py`:

    ```python
    # Hint for PyInstaller to find the Windows backend
    try:
        import keyring.backends.Windows
    except ImportError:
        pass
    ```

3.  **Run the Build Command:**
    From the project root, run this command to build the `.exe`:

    ```bash
    # Make sure you're on Windows and in the project's root directory
    pyinstaller --onefile --windowed ^
        --collect-all winrt-windows ^
        --add-data "icon\Cyber-Cage.png;icon" ^
        cipherapp.py
    ```

      * `--onefile --windowed`: Creates a single, windowed executable.
      * `--collect-all winrt-windows`: **Crucial** for bundling all Windows Hello biometric functions.
      * `--add-data "icon\..."`: Packages the `Cyber-Cage.png` icon so it appears in the app window.

4.  **Find Your App:**
    Your `cipherapp.exe` will be in the `dist/` folder.

### 🌎 Self-Hosting (Optional)

The desktop app is a client that connects to an API server. You can host your own private CipherDrop server for maximum privacy.

The server is a lightweight Python file (`server.py`).

1.  **Install Server Dependencies:**
    From the project root (preferably in a virtual environment):

    ```bash
    pip install -r requirements.txt
    ```

2.  **Create `.env` file:**
    Create a file named `.env` in the same directory. This is where you'll put your server's secret key.

    ```ini
    # Generate a strong random secret with:
    # python -c "import secrets; print(secrets.token_hex(32))"
    JWT_SECRET="your_super_strong_random_secret_here"
    ```

3.  **Run the Server:**

    ```bash
    # This will start the server on http://localhost:8000
    uvicorn server:app --host 0.0.0.0 --port 8000
    ```

4.  **Connect Your Client:**
    Open your `cipherapp.exe`, and in the API URL box, type `http://localhost:8000`. You can now create accounts and share files using your own private server.
