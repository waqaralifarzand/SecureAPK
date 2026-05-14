"""SecureAPK bootstrap script. Run once after `pip install -r requirements.txt`.

Verifies Python version, initialises the SQLite database, creates working
directories, and probes for external tools (Jadx, ADB, emulator).

Missing external tools do NOT cause failure — analysis fallback chains handle
their absence. See ARCHITECTURE.md §10 and §13.
"""
from __future__ import annotations

import shutil
import subprocess
import sys

import config
from modules import db_manager


def check_python() -> bool:
    ok = sys.version_info >= (3, 11)
    print(f"{'OK ' if ok else 'X  '} Python {sys.version_info.major}.{sys.version_info.minor} (>= 3.11 required)")
    return ok


def check_db() -> bool:
    try:
        db_manager.init_db()
    except Exception as e:
        print(f"X   Database init failed: {e}")
        return False
    print(f"OK  Database initialised at {config.DATABASE_PATH}")
    return True


def check_dirs() -> bool:
    for p in (config.UPLOADS_PATH, config.REPORTS_PATH, config.DATABASE_PATH.parent):
        p.mkdir(parents=True, exist_ok=True)
    print("OK  Working directories created (uploads/, reports/, database/)")
    return True


def _which(name: str) -> str | None:
    return shutil.which(name)


def check_jadx() -> bool:
    path = config.JADX_PATH or "jadx"
    found = _which(path)
    if found:
        print(f"OK  Jadx found: {found}")
        return True
    print("!   Jadx not in PATH. Source analysis will fall back to DEX string extraction.")
    print("    Install: https://github.com/skylot/jadx/releases")
    return False


def check_adb() -> bool:
    path = config.ADB_PATH or "adb"
    found = _which(path)
    if found:
        print(f"OK  ADB found: {found}")
        return True
    print("!   ADB not in PATH. Dynamic analysis will be skipped if requested.")
    print("    Install Android platform-tools from https://developer.android.com/tools/releases/platform-tools")
    return False


def check_emulator() -> bool:
    adb = config.ADB_PATH or "adb"
    if not _which(adb):
        print("!   Emulator check skipped (adb missing).")
        return False
    try:
        out = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        print("!   `adb devices` failed or timed out.")
        return False
    for line in out.stdout.splitlines()[1:]:
        if line.strip().endswith("device"):
            print(f"OK  Emulator running: {line.split()[0]}")
            return True
    print("!   No emulator running. Start one via Android Studio for dynamic analysis.")
    return False


def main() -> int:
    print(f"--- {config.TOOL_NAME} {config.TOOL_VERSION} setup ---")
    if not check_python():
        return 1
    check_dirs()
    if not check_db():
        return 1
    check_jadx()
    check_adb()
    check_emulator()
    print("--- setup complete ---")
    return 0


if __name__ == "__main__":
    sys.exit(main())
