"""
SecureAPK Setup Script
Run: python setup.py
"""
import subprocess
import sys
import os

def run(cmd, check=True):
    print(f"  → {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"    ✗ Failed: {result.stderr.strip()}")
        return False
    return True

def check_command(cmd):
    try:
        subprocess.run([cmd, '--version'], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

print("=" * 60)
print("  SecureAPK — Setup Script")
print("  Lahore Garrison University FYP")
print("=" * 60)
print()

# 1. Create directories
print("[1/4] Creating project directories...")
for d in ['database', 'reports', os.path.join('static', 'uploads')]:
    os.makedirs(d, exist_ok=True)
    print(f"  ✓ {d}/")

# 2. Install Python packages
print("\n[2/4] Installing Python dependencies...")
packages = ['flask', 'werkzeug', 'pyaxmlparser', 'reportlab']
for pkg in packages:
    print(f"  Installing {pkg}...")
    ok = run([sys.executable, '-m', 'pip', 'install', '--quiet', '--upgrade', pkg], check=False)
    if ok:
        print(f"  ✓ {pkg}")
    else:
        print(f"  ✗ {pkg} — try: pip install {pkg}")

# 3. Check optional tools
print("\n[3/4] Checking optional tools...")

jadx_ok = check_command('jadx')
print(f"  {'✓' if jadx_ok else '✗'} jadx {'(found)' if jadx_ok else '(NOT FOUND — download from https://github.com/skylot/jadx/releases)'}")

aapt_ok = check_command('aapt')
print(f"  {'✓' if aapt_ok else '○'} aapt {'(found)' if aapt_ok else '(optional — part of Android SDK build-tools)'}")

adb_ok = check_command('adb')
print(f"  {'✓' if adb_ok else '○'} adb {'(found)' if adb_ok else '(optional — required for dynamic analysis)'}")

# 4. Initialize database
print("\n[4/4] Initializing database...")
try:
    sys.path.insert(0, os.path.dirname(__file__))
    from modules.db_manager import init_db
    init_db()
    print("  ✓ SQLite database initialized at database/secureapk.db")
except Exception as e:
    print(f"  ✗ DB init failed: {e}")

# Summary
print()
print("=" * 60)
print("  Setup Complete!")
print()
print("  To start SecureAPK:")
print("    python app.py")
print()
print("  Then open: http://localhost:5000")
print()
if not jadx_ok:
    print("  ⚠ Install Jadx for full source code analysis:")
    print("    https://github.com/skylot/jadx/releases")
    print()
if not adb_ok:
    print("  ⚠ Install Android Studio for dynamic analysis:")
    print("    https://developer.android.com/studio")
    print()
print("=" * 60)
