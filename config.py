import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DATABASE_PATH = BASE_DIR / "database" / "secureapk.db"
UPLOADS_PATH = BASE_DIR / "uploads"
REPORTS_PATH = BASE_DIR / "reports"

JADX_PATH = os.environ.get("SECUREAPK_JADX_PATH", None)
ADB_PATH = os.environ.get("SECUREAPK_ADB_PATH", None)
AAPT_PATH = os.environ.get("SECUREAPK_AAPT_PATH", None)

MAX_UPLOAD_SIZE_MB = 200
ANALYSIS_TIMEOUT_SECONDS = 300
JADX_TIMEOUT_SECONDS = 180
DYNAMIC_LOGCAT_DURATION_SECONDS = 30
DYNAMIC_MONKEY_EVENT_COUNT = 50

SEVERITY_WEIGHTS = {"HIGH": 10, "MEDIUM": 5, "LOW": 2}
CATEGORY_MULTIPLIERS = {
    "Hardcoded Secrets": 1.5,
    "Insecure Communication": 1.4,
    "Weak Cryptography": 1.4,
    "SSL/TLS Validation Bypass": 1.5,
    "Insecure Data Storage": 1.3,
    "WebView Security": 1.3,
    "Information Leakage": 1.2,
    "Code Execution": 1.4,
    "IPC Security": 1.2,
}
RISK_THRESHOLDS = {"LOW_MAX": 30, "MEDIUM_MAX": 70}
SCORE_NORMALIZATION_DIVISOR = 200

HOST = os.environ.get("SECUREAPK_HOST", "127.0.0.1")
PORT = int(os.environ.get("SECUREAPK_PORT", "5000"))
DEBUG = os.environ.get("SECUREAPK_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("SECUREAPK_SECRET_KEY", "dev-only-secret-change-in-production")

TOOL_NAME = "SecureAPK"
TOOL_VERSION = "1.0.0"
