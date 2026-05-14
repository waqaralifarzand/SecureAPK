# SecureAPK

> A locally-hosted hybrid static + dynamic Android security analysis framework, built as a final-year project for BS-DFCS at Lahore Garrison University.

SecureAPK is what you get when you take MobSF's analysis approach, strip out the enterprise complexity, and add three differentiators that the global open-source tools don't have: **forensic-grade reports** with cryptographic chain-of-custody, a **Pakistan State Bank cybersecurity-framework compliance ruleset**, and an **educational mode** that turns every finding into a teaching example.

It runs entirely on your laptop. No cloud, no accounts, no telemetry.

---

## What makes SecureAPK different from MobSF

### 1. Forensic-grade reporting

Every generated PDF embeds the **SHA-256 hash** of the analysed APK on the cover, an ISO-8601 timestamp pair, a tool-version stamp, and a chronological **audit-log appendix** of every state change during the analysis. Re-hashing the uploaded APK with `sha256sum` and matching the value on the PDF cover establishes that the report describes a specific, unmodified artefact analysed at a specific time. ReportLab is told not to compress content streams, so the hash is literally `grep`-able in the raw PDF bytes — a forensic examiner can verify integrity without parsing the document.

MobSF reports are excellent for developers but contain no cryptographic proof and no chain-of-custody metadata. That gap is the differentiator.

### 2. SBP banking compliance

When you tick the **SBP Compliance** toggle, a dedicated rule pack drawn from the State Bank of Pakistan Cybersecurity Framework runs against the static-analysis results. Ten rules covering TLS enforcement, certificate pinning, sensitive-data logging, hardcoded credentials, screen-capture protection, root detection, session timeout, plaintext storage, biometric auth, and `networkSecurityConfig`. Each rule returns one of four statuses: COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE, or MANUAL_REVIEW. A banking-app heuristic detects likely Pakistani banking apps automatically from package/app-name tokens and the OTP+contacts+network permission combo.

MobSF is engineered for global enterprise audiences and has no concept of regional banking compliance.

### 3. Educational mode

When the **Educational Mode** toggle is enabled, every Phase 3 source-code finding gets an inline expand button. Click it and the card unfolds to show: the **vulnerable** code (red tint), the **fixed** equivalent (green tint), and a plain-English **why this matters** explanation (neutral). The same three panels appear inline in the PDF report when the mode is on. Built for university students learning Android security from real APKs.

MobSF reports list findings but don't teach.

---

## Quick start

```bash
git clone https://github.com/waqaralifarzand/SecureAPK
cd SecureAPK
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python setup.py                        # creates DB + dirs, probes Jadx/ADB
python app.py                          # http://127.0.0.1:5000
```

Open `http://127.0.0.1:5000`, drag in any `.apk`, optionally tick the three toggles (Dynamic / SBP / Educational), and click **Start Analysis**. The result page polls until the orchestrator completes — typically under a minute for a small APK without Dynamic enabled.

Run the test suite:

```bash
pytest -v                              # 42 tests
pytest --cov=modules tests/            # with coverage
```

---

## Detailed setup

### Required

- **Python 3.11+** (locked in `CLAUDE.md` §4). Python 3.13 is fine.
- Pip dependencies pinned in `requirements.txt`: Flask 3.x, PyAXMLParser, ReportLab 4.x, pytest 8.x.

### Optional (the analyzer gracefully degrades when missing)

- **Jadx 1.5+** for decompilation in Phase 3. Without it, the source analyzer falls back to printable-string extraction from `classes*.dex`. Install from <https://github.com/skylot/jadx/releases> and make sure `jadx` is on PATH. (Or set the `SECUREAPK_JADX_PATH` environment variable.)
- **Android SDK `platform-tools`** (specifically `adb`) for Phase 4 dynamic analysis. Without it, the Dynamic tab shows a clean "no emulator detected" banner — no crash.
- **`aapt`** is consulted only as a fallback when PyAXMLParser fails. Optional.
- **Android emulator** (a running AVD from Android Studio). Required only for actual dynamic analysis, not for static work.

### Environment variables (all optional)

| Variable | Default | Purpose |
|---|---|---|
| `SECUREAPK_JADX_PATH` | `jadx` (PATH lookup) | Override Jadx binary path |
| `SECUREAPK_ADB_PATH`  | `adb` (PATH lookup)  | Override ADB binary path |
| `SECUREAPK_AAPT_PATH` | `aapt` (PATH lookup) | Override aapt binary path |
| `SECUREAPK_HOST`      | `127.0.0.1` | Flask listen host |
| `SECUREAPK_PORT`      | `5000`      | Flask listen port |
| `SECUREAPK_DEBUG`     | `false`     | Enable Flask debug mode |

---

## Usage walkthrough

1. **Open `http://127.0.0.1:5000`.** You'll see a dark-themed upload page.
2. **Drag or pick an APK** (size limited to 200 MB).
3. **Toggle options:**
   - *Enable Dynamic Analysis* — only if you have a running Android emulator.
   - *Enable SBP Banking Compliance Check* — runs the SBP rule pack (recommended for any Pakistani banking app).
   - *Enable Educational Mode* — adds the inline expand buttons on source findings.
4. **Click Start Analysis.** You're redirected to `/analysis/<id>` which polls until completion.
5. **Read the result page.** Tabs: Manifest, Source Code, Dynamic (if enabled), Risk, Permissions, SBP Compliance (if enabled). The header shows a colour-coded risk badge.
6. **Click Download PDF Report.** Verify the cover-page SHA-256 matches `sha256sum <your.apk>`. The PDF also contains an audit-log appendix proving the chain of custody.
7. **Optional forensic verification:**
   ```bash
   sha256sum your.apk
   grep -c <that-hash> reports/<analysis-id>.pdf
   # -> 1 (the hash is literally embedded in the PDF body)
   ```
8. **Dashboard.** `/dashboard` lists every analysis with a delete button.

---

## Architecture overview

```
upload  ->  Flask /upload  ->  daemon thread  ->  modules/analyzer.py (orchestrator)
                                                        |
              ┌─────────────────────────┬──────────────┴────────────────┬──────────────────┐
        Phase 2: Manifest        Phase 3: Source           Phase 4: Dynamic       Phase 7: SBP
        PyAXMLParser ->          Jadx ->                   ADB devices ->         consumes Phase 2/3/4
        aapt ->                  classes.dex strings       install -> monkey ->   produces compliance
        dex strings              30+ regex patterns        logcat -> uninstall    statuses
              |                         |                         |                       |
              └────────────────────────────────────────────────────────────────────────────┘
                                          v
                              Phase 5: Risk Engine
                              (weighted scoring + OWASP + CWE)
                                          v
                              Phase 6: ReportLab PDF
                              (cover + SHA-256 + audit appendix)
                                          v
                              status='completed', pdf_path on row
```

- All detection rules live in **`modules/patterns/`** as plain Python data — analyzers consume; editing one file changes the rule.
- The **orchestrator** (`modules/analyzer.py`) is the *only* module that knows the phase sequence. Phases never call each other directly.
- **`modules/db_manager.py`** owns the seven-table SQLite schema. No raw SQL lives outside that module.
- **Fallback chains** are mandatory: manifest (PyAXMLParser → aapt → DEX strings), source (Jadx → DEX strings), dynamic (emulator → skipped). The analyzer never crashes because a tool is missing.

For the full technical spec see `ARCHITECTURE.md`. For the project identity and hard rules see `CLAUDE.md`.

---

## Adding new detection patterns

Most contributors will want to add detection patterns. The catalog files are pure Python data:

```python
# modules/patterns/vuln_patterns.py
{
    "id": "MY_NEW_PATTERN",
    "category": "Hardcoded Secrets",            # must be one of the 9 categories
    "severity": "HIGH",                          # HIGH / MEDIUM / LOW
    "regex": r"my-new-regex-here",
    "title": "Short, action-oriented title",
    "description": "What the pattern catches and why it matters.",
    "owasp_id": "M1",                            # OWASP Mobile Top 10 2024
    "cwe_id": "CWE-798",
    "remediation": {                             # required (Phase 8 reads this)
        "vulnerable_snippet": "the bad code",
        "fixed_snippet": "the corrected version",
        "explanation": "plain-English why this is dangerous",
    },
}
```

Then add an entry to `modules/patterns/owasp_cwe_map.py` if the category isn't already mapped. The import-time integrity assertions in `vuln_patterns.py` will fail loudly if you miss a required field.

For dangerous permissions edit `modules/patterns/permissions.py`. For runtime event categories edit `modules/patterns/runtime_events.py`. For SBP rules edit `modules/patterns/sbp_rules.py` and add a new `_check_*` callable.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Phase 2 always reports `parser_used=dex_strings` | PyAXMLParser is failing silently | Check the APK isn't corrupted; install `aapt` for the middle fallback |
| Phase 3 reports `decompiler_used=dex_strings` even on real APKs | Jadx not on PATH | Install Jadx 1.5+ or set `SECUREAPK_JADX_PATH` |
| Dynamic tab shows red "skipped_no_emulator" banner | No AVD running | Open Android Studio → Device Manager → start an AVD, then re-upload |
| `Address already in use` on `python app.py` | Port 5000 taken | `export SECUREAPK_PORT=5050` |
| PDF cover hash doesn't match `sha256sum` | The uploaded file was modified after upload (uploads/ rename, etc.) | Compute the hash on the original *before* uploading; the cover hash is computed on the bytes stored in `uploads/` |
| SBP tab missing | The analysis was run with SBP disabled | Re-upload with the SBP toggle on |

---

## References

- **OWASP Mobile Top 10 (2024)** — <https://owasp.org/www-project-mobile-top-10/>
- **CWE database** — <https://cwe.mitre.org/>
- **State Bank of Pakistan Cybersecurity Framework** — banking-app compliance source
- **DIVA (Damn Insecure & Vulnerable App)** — <https://github.com/payatu/diva-android>
- **InsecureShop** — <https://github.com/hax0rgb/InsecureShop>
- **AndroGoat** — <https://github.com/satishpatnayak/AndroGoat>
- **Jadx** — <https://github.com/skylot/jadx>
- **ReportLab Platypus** — <https://www.reportlab.com/docs/reportlab-userguide.pdf>

---

## Viva prep checklist

Run through this list before the panel. Each item is a thing you should be able to **demo on the laptop in under 60 seconds** or **explain in under 90 seconds**.

### Concepts

- [ ] I can explain why SecureAPK exists and how it's different from MobSF in one sentence per differentiator.
- [ ] I can name the 9 source-code categories from memory: Hardcoded Secrets, Insecure Communication, Weak Cryptography, Insecure Data Storage, Information Leakage, WebView Security, Code Execution, IPC Security, SSL/TLS Validation Bypass.
- [ ] I can explain the OWASP Mobile Top 10 (2024) categories most relevant to my findings.
- [ ] I can name at least 5 of the 10 SBP rules and what each checks.
- [ ] I can explain the six-phase orchestrator flow and why phase 7 (SBP) runs before phase 5 (Risk).

### Architecture

- [ ] I can point to where the fallback chains live (manifest, source, dynamic) and explain why each is needed.
- [ ] I can explain why `modules/patterns/` separates data from logic.
- [ ] I can explain the per-(pattern_id, file) deduplication in Phase 3 and why it matters.
- [ ] I can name all 7 SQLite tables and what each stores.
- [ ] I can explain how the `breakdown_by_phase.sbp` bucket fills (the risk-engine join with `sbp_findings`).

### Demos

- [ ] Upload a benign APK → see LOW classification, no SBP tab (when disabled), clean PDF.
- [ ] Upload DIVA (or any vulnerable APK) → see HIGH classification, multiple OWASP categories triggered.
- [ ] Upload an APK with SBP enabled → show the SBP Compliance tab with the four status pill counts.
- [ ] Upload an APK with Educational Mode → click the expand button on a source finding, show the three panels live.
- [ ] Download the PDF → open in a viewer → verify the SHA-256 on the cover matches `sha256sum <your.apk>` in a terminal.
- [ ] `grep <hash> reports/<id>.pdf` → returns 1. Explain why the PDF isn't compressed and what this gives us forensically.
- [ ] Run `pytest -v` → all 42 tests green in under 10 seconds.

### Defensive answers

- [ ] If the panel asks why you didn't use Frida, I can cite CLAUDE.md §6 rule 10 and explain the literature-review consequence of scope drift.
- [ ] If the panel asks why ReportLab not WeasyPrint, I can cite the no-headless-browser principle and the reproducibility win from `pageCompression=0 + invariant=True`.
- [ ] If the panel asks why SQLite not Postgres, I can cite single-user local deployment + zero-install.
- [ ] If the panel asks how I'd extend SBP to other frameworks (e.g., RBI for Indian banking), I can describe adding a new rule pack file and a new toggle without touching the orchestrator.

---

## Planning files

These four files are the project's source of truth — they were written before any code:

- **`CLAUDE.md`** — project identity, locked tech stack, design tokens, hard rules.
- **`ARCHITECTURE.md`** — folder tree, routes, database schema, fallback chains, data shapes.
- **`PHASES.md`** — execution roadmap, phase by phase.
- **`SCRATCHPAD.md`** — chronological session memory, every mid-execution decision (D-1 through D-23 logged).

---

## Project metadata

- **Student:** Nayab Kazim (FA-22/BS DFCS/081)
- **Programme:** BS Digital Forensics and Cyber Security
- **Institution:** Lahore Garrison University, Department of Criminology
- **Session:** 2022–2026
- **Tool version:** 1.0.0
