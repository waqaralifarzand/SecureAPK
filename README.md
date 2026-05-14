# SecureAPK
## A Hybrid Static and Dynamic Security Analysis Framework for Android Applications

**Final Year Project — BS Digital Forensics & Cyber Security**  
**Student:** Nayab Kazim (FA-22/BS DFCS/081)  
**Institution:** Lahore Garrison University, Department of Criminology  
**Supervisor:** [Supervisor Name]

---

## 📋 Project Overview

SecureAPK is a web-based Android application security analysis framework that automates the security assessment process through a combination of static and dynamic analysis techniques. It helps developers and forensic investigators detect security weaknesses in Android APK files.

### Core Capabilities

| Phase | Description |
|-------|-------------|
| **Phase 1** | System Design — Flask backend, SQLite DB, modular architecture |
| **Phase 2** | Static Analysis — Manifest inspection via PyAXMLParser |
| **Phase 3** | Static Analysis — Source code scanning via Jadx (30+ vuln patterns) |
| **Phase 4** | Dynamic Analysis — Runtime monitoring via ADB + Android Emulator |
| **Phase 5** | Risk Scoring — Weighted scoring with OWASP Mobile Top 10 / CWE mapping |
| **Phase 6** | Reporting — Downloadable PDF reports with full findings |

---

## 🏗 Project Structure

```
SecureAPK/
├── app.py                    # Flask application — all routes
├── requirements.txt          # Python dependencies
├── setup.py                  # Automated setup script
├── test_runner.py            # Phase 6: Testing & Evaluation
│
├── modules/
│   ├── __init__.py
│   ├── db_manager.py         # SQLite database operations
│   ├── static_manifest.py    # Phase 2: Manifest analysis
│   ├── static_sourcecode.py  # Phase 3: Source code vulnerability scanning
│   ├── dynamic_analysis.py   # Phase 4: ADB-based runtime monitoring
│   ├── risk_engine.py        # Phase 5: Risk scoring engine
│   └── report_generator.py   # PDF/HTML report generation
│
├── templates/
│   ├── index.html            # Home / upload page
│   ├── result.html           # Analysis results (tabbed view)
│   └── dashboard.html        # Analysis history dashboard
│
├── static/
│   ├── css/
│   │   ├── main.css          # Main dark-themed stylesheet
│   │   └── result.css        # Result page styles
│   └── js/
│       ├── main.js           # Upload flow & progress animations
│       └── result.js         # Tab switching & result animations
│
├── database/                 # SQLite DB stored here (auto-created)
├── reports/                  # Generated PDF reports (auto-created)
└── static/uploads/           # Uploaded APKs (auto-created)
```

---

## ⚙️ Installation & Setup

### System Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Windows 10/11, Ubuntu 20.04+, macOS 12+ |
| CPU | Intel Core i5 or higher |
| RAM | Minimum 8 GB (16 GB recommended for dynamic analysis) |
| Storage | 100 GB free |
| Python | 3.11 or newer |

### Step 1 — Clone / Extract the Project

```bash
# If using Git:
git clone <repo-url>
cd SecureAPK

# Or extract the ZIP and navigate to the folder
```

### Step 2 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

Dependencies installed:
- `flask` — Web framework
- `werkzeug` — File handling utilities
- `pyaxmlparser` — Android manifest parsing
- `reportlab` — PDF report generation

### Step 3 — Install Jadx (for Source Code Analysis)

Jadx is required for APK decompilation in Phase 3.

**Windows:**
1. Download `jadx-<version>-with-jre-win.zip` from https://github.com/skylot/jadx/releases
2. Extract and add the `bin/` folder to your system PATH

**Linux/macOS:**
```bash
# Via package manager (Linux):
sudo snap install jadx

# Or download the release ZIP:
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d jadx
sudo ln -s $(pwd)/jadx/bin/jadx /usr/local/bin/jadx
```

**Verify:**
```bash
jadx --version
```

> **Note:** If Jadx is not installed, SecureAPK automatically falls back to string extraction from DEX files. You will still get partial source code findings.

### Step 4 — (Optional) Android Emulator for Dynamic Analysis

Required only if you want to enable Phase 4 dynamic analysis.

1. Install **Android Studio** from https://developer.android.com/studio
2. Open Android Studio → **Device Manager** → **Create Virtual Device**
3. Choose a device (e.g., Pixel 6) with API 30+
4. Start the emulator
5. Verify ADB detects it:
   ```bash
   adb devices
   # Should show: emulator-5554   device
   ```

### Step 5 — Run the Application

```bash
python app.py
```

Open your browser and navigate to: **http://localhost:5000**

---

## 🚀 How to Use

### Uploading an APK

1. Open **http://localhost:5000** in your browser
2. Drag and drop an APK file (or click to browse)
3. Optionally enable **Dynamic Analysis** (requires emulator)
4. Click **Start Analysis**
5. Wait for all phases to complete (~30–120 seconds depending on APK size)
6. You will be redirected to the results page automatically

### Reading the Results

The results page has 5 tabs:

| Tab | Contents |
|-----|----------|
| **Manifest Analysis** | App metadata, permission findings, exported components, config issues |
| **Source Code** | Vulnerability findings with file location and code snippets |
| **Dynamic Analysis** | Runtime logs, network connections, suspicious events |
| **Risk Details** | Score breakdown, OWASP/CWE mapping, top critical issues |
| **Permissions** | All requested permissions with danger indicators |

### Downloading Reports

Click **"⬇ Download PDF Report"** in the top-right to download a structured PDF report.

### Dashboard

Navigate to **/dashboard** to view all past analyses. You can:
- Click **View** to open a past result
- Click **PDF** to download the report
- Click **Del** to delete an analysis

---

## 🔬 Technical Details

### Phase 2 — Manifest Analysis

**Tool:** PyAXMLParser  
**Input:** AndroidManifest.xml (extracted from APK ZIP)  
**Detects:**
- 37 dangerous/sensitive permissions (READ_SMS, RECORD_AUDIO, ACCESS_FINE_LOCATION, etc.)
- Exported Activities, Services, Receivers, Providers without permission protection
- `android:usesCleartextTraffic="true"` — HTTP allowed
- `android:debuggable="true"` — debug builds
- `android:allowBackup="true"` — ADB backup exposure
- Missing Network Security Configuration

**Fallback chain:** PyAXMLParser → aapt → raw binary string extraction

### Phase 3 — Source Code Analysis

**Tool:** Jadx (Java decompiler)  
**Input:** Decompiled .java source files  
**Vulnerability categories detected (30+ patterns):**

| Category | Examples |
|----------|---------|
| Hardcoded Secrets | passwords, API keys, tokens, Google API keys |
| Insecure Communication | HTTP URLs, disabled hostname verification, SSL bypass |
| Weak Cryptography | MD5, SHA-1, DES, AES-ECB, insecure PRNG |
| Insecure Data Storage | World-readable files, unprotected SharedPreferences |
| Information Leakage | Sensitive data in Android logs |
| WebView Security | JavaScript enabled, addJavascriptInterface, file access |
| Code Execution | Runtime.exec() usage |
| IPC Security | Unprotected broadcasts, mutable PendingIntents |

**Fallback:** If Jadx is unavailable, extracts printable strings from DEX files.

### Phase 4 — Dynamic Analysis

**Tools:** ADB (Android Debug Bridge), Android Emulator  
**Process:**
1. Detect connected emulator via `adb devices`
2. Install APK: `adb install -r -t <apk>`
3. Launch via: `adb shell monkey -p <package> -c android.intent.category.LAUNCHER 1`
4. Capture logs: `adb logcat` for 30 seconds
5. Observe network: `adb shell netstat -n`
6. Analyze logs for: cleartext HTTP, credentials in logs, SSL errors, command execution
7. Uninstall APK after analysis

**Graceful degradation:** If no emulator is detected, shows setup instructions.

### Phase 5 — Risk Scoring

**Algorithm:**
```
severity_weight = { HIGH: 10, MEDIUM: 5, LOW: 2 }
category_multiplier = { "Hardcoded Secrets": 1.5, "Insecure Communication": 1.4, ... }
raw_score = Σ (weight × multiplier) across all findings
normalized = min(100, (raw_score / 200) × 100)
```

**Classification:**
- **Low Risk:** Score 0–30
- **Medium Risk:** Score 31–70
- **High Risk:** Score 71–100

**Standards References:**
- OWASP Mobile Security Testing Guide (MSTG)
- OWASP Mobile Top 10 (2024)
- Common Weakness Enumeration (CWE)
- SBP Cybersecurity Framework (for banking apps)

---

## 🧪 Phase 6 — Testing & Evaluation

Run the automated test suite:

```bash
python test_runner.py
```

This tests:
1. **Functional testing** — all analysis modules return correct structure
2. **Detection accuracy** — known-vulnerable APK patterns are flagged
3. **Performance evaluation** — measures analysis time per APK size
4. **Report generation** — verifies PDF output is created

For manual testing, recommended APK samples:
- **DIVA Android** — https://github.com/payatu/diva-android (intentionally vulnerable)
- **InsecureShop** — https://github.com/hax0rgb/InsecureShop
- **AndroGoat** — https://github.com/satishpatnayak/AndroGoat

---

## 🔒 Security Considerations

- Uploaded APKs are stored locally in `static/uploads/` — do not deploy publicly without authentication
- Analysis runs in the same Python process — for production, consider sandboxing with Docker
- Dynamic analysis modifies the connected emulator — use a dedicated test device/emulator
- Reports may contain sensitive findings — store securely

---

## 📚 Dependencies & Licenses

| Library | Version | License | Purpose |
|---------|---------|---------|---------|
| Flask | ≥3.0 | BSD | Web framework |
| Werkzeug | ≥3.0 | BSD | WSGI utilities |
| PyAXMLParser | ≥0.3.27 | MIT | Android manifest parsing |
| ReportLab | ≥4.0 | BSD | PDF generation |
| Jadx | ≥1.5 | Apache 2.0 | APK decompilation (external tool) |
| ADB | Included with Android SDK | Apache 2.0 | Device communication |

---

## 👩‍💻 Developer Notes

### Adding New Vulnerability Patterns

Edit `modules/static_sourcecode.py` and add to the `VULN_PATTERNS` list:

```python
(r'your_regex_pattern',
 'HIGH',                          # Severity: HIGH / MEDIUM / LOW
 'Short Finding Title',
 'Detailed description of the vulnerability and its impact.',
 'Category Name'),                # Used for grouping and OWASP mapping
```

### Adding New Dangerous Permissions

Edit `modules/static_manifest.py` and add to `HIGH_RISK_PERMISSIONS`:

```python
'android.permission.YOUR_PERMISSION': ('HIGH', 'Description of why this is dangerous'),
```

### Extending Risk Score Categories

Edit `modules/risk_engine.py`:
- `SEVERITY_WEIGHTS` — change scoring per severity level
- `CATEGORY_MULTIPLIERS` — tune how much each category contributes
- `THRESHOLDS` — change Low/Medium/High boundaries

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: pyaxmlparser` | Run `pip install pyaxmlparser` |
| `ModuleNotFoundError: reportlab` | Run `pip install reportlab` |
| Jadx not found | Install Jadx and add to PATH; or skip — fallback will activate |
| `adb: command not found` | Install Android SDK platform-tools and add to PATH |
| No emulator detected | Start Android Emulator via Android Studio first |
| APK too large / timeout | Increase `MAX_CONTENT_LENGTH` in `app.py` and Jadx timeout in `static_sourcecode.py` |
| PDF download is HTML file | ReportLab not installed — run `pip install reportlab` |

---

## 📝 References

1. OWASP Mobile Security Testing Guide (MSTG) — https://owasp.org/www-project-mobile-security-testing-guide/
2. OWASP Mobile Top 10 (2024) — https://owasp.org/www-project-mobile-top-10/
3. Android Security Best Practices — https://developer.android.com/topic/security/best-practices
4. CWE/SANS Top 25 — https://cwe.mitre.org/top25/
5. PyAXMLParser — https://github.com/appknox/pyaxmlparser
6. Jadx — https://github.com/skylot/jadx
7. Android Debug Bridge — https://developer.android.com/tools/adb

---

*SecureAPK © 2024 — Nayab Kazim — Lahore Garrison University*
