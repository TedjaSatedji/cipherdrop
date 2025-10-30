# app_client.py
import os, sys
from pathlib import Path

# Resolve paths both in normal Python and PyInstaller (_MEIPASS)
ROOT = Path(__file__).resolve().parent
BASE = Path(getattr(sys, "_MEIPASS", ROOT))   # <- bundle dir at runtime

# Make bundled packages importable (auth/, crypto/, stego/)
sys.path.insert(0, str(BASE))

# Optional default API
os.environ.setdefault("CIPHERDROP_API", "http://localhost:8000")

# Point to the real Streamlit app inside the bundle
APP = str(BASE / "streamlit_app.py")

# Extra safety: ensure we run from the bundle root
os.chdir(BASE)

from streamlit.web.bootstrap import run as st_run
st_run(APP, "", [], flag_options={
    "server.port": 8501,              # change if you want 3000
    "browser.gatherUsageStats": False,
    "server.headless": True
})
