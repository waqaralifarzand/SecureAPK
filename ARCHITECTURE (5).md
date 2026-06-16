# ARCHITECTURE.md — SecureAPK Technical Structure

> **For Claude Code:** Read this AFTER `CLAUDE.md`. This file is the technical bible — folder structure, routes, database schema, data shapes, fallback chains, and the orchestrator contract. Implementation decisions inside a phase reference back here.

> **For Nayab:** This file answers "how is it built?" When a panel asks about a specific module, route, or database table, the answer is here.

---

## 1. Folder structure

```
SecureAPK/
│
├── app.py                          # Flask routes only. Thin. No analysis logic here.
├── config.py                       # Tunables: paths, thresholds, weights, timeouts.
├── setup.py                        # Bootstrap script: verify Python/Jadx/ADB, init DB.
├── requirements.txt                # Python deps (pinned versions).
├── README.md                       # User-facing setup and usage docs.
│
├── CLAUDE.md                       # Project identity (the planning file).
├── ARCHITECTURE.md                 # This file.
├── PHASES.md                       # Execution roadmap.
├── SCRATCHPAD.md                   # Session memory — updated after each phase.
│
├── modules/
│   ├── __init__.py
│   ├── analyzer.py                 # ORCHESTRATOR. Only file that knows the phase sequence.
│   ├── manifest_analyzer.py        # Phase 2 — manifest inspection (PyAXMLParser + fallback chain).
│   ├── source_analyzer.py          # Phase 3 — Jadx decompile + 30+ regex patterns.
│   ├── dynamic_analyzer.py         # Phase 4 — ADB-driven runtime monitoring (REBUILT from scratch).
│   ├── risk_engine.py              # Phase 5 — weighted scoring, OWASP/CWE mapping, classification.
│   ├── report_generator.py         # Phase 6 — PDF generation via ReportLab.
│   │
│   ├── forensic.py                 # NEW Feature 1 — SHA-256, chain-of-custody, audit log.
│   ├── sbp_compliance.py           # NEW Feature 2 — Pakistan SBP banking ruleset.
│   ├── educational.py              # NEW Feature 3 — vulnerable/fixed snippet + explanation per finding.
│   │
│   ├── db_manager.py               # All SQLite operations. No raw SQL outside this module.
│   │
│   └── patterns/                   # DATA, not logic. Each file is a catalog the analyzers consume.
│       ├── __init__.py
│       ├── permissions.py          # 37 dangerous Android permissions + severity + description.
│       ├── vuln_patterns.py        # 30+ regex patterns across 9 categories + remediation content.
│       ├── runtime_events.py       # 10 runtime event categories + detection patterns.
│       ├── sbp_rules.py            # State Bank of Pakistan cybersecurity framework checks.
│       └── owasp_cwe_map.py        # Mapping: category → OWASP MTW10 (2024) id + CWE id.
│
├── templates/                      # Jinja2 templates.
│   ├── base.html                   # Common HTML shell (nav, footer, CSS imports).
│   ├── index.html                  # Home / upload page.
│   ├── result.html                 # Tabbed results page.
│   ├── dashboard.html              # Analysis history table.
│   └── _partials/
│       ├── finding_card.html       # Reusable finding card (with optional educational expansion).
│       ├── risk_badge.html         # Low/Med/High badge.
│       └── tab_nav.html            # Tab navigation strip.
│
├── static/
│   ├── css/
│   │   ├── main.css                # Dark theme, layout, typography.
│   │   ├── result.css              # Result page specifics (tabs, findings).
│   │   └── dashboard.css           # Dashboard table styling.
│   └── js/
│       ├── main.js                 # Upload flow, drag/drop, mode toggles.
│       ├── result.js               # Tab switching, educational mode expand/collapse.
│       └── status_poller.js        # Polls /api/analysis/<id>/status during running analyses.
│
├── tests/                          # pytest. Target: 34+ tests.
│   ├── __init__.py
│   ├── conftest.py                 # Shared fixtures (test APKs, DB factory).
│   ├── test_manifest_analyzer.py
│   ├── test_source_analyzer.py
│   ├── test_dynamic_analyzer.py
│   ├── test_risk_engine.py
│   ├── test_report_generator.py
│   ├── test_forensic.py
│   ├── test_sbp_compliance.py
│   ├── test_educational.py
│   ├── test_db_manager.py
│   ├── test_orchestrator.py        # End-to-end orchestrator with mocked phases.
│   └── fixtures/
│       └── sample_apks/            # Test APKs (DIVA, InsecureShop, AndroGoat references).
│
├── database/                       # Auto-created at runtime.
│   └── secureapk.db                # SQLite database file.
│
├── reports/                        # Auto-created. Generated PDF reports — preserved as evidence.
│
└── uploads/                        # Auto-created. Uploaded APKs — preserved per chain-of-custody.
```

**Design principles enforced by this structure:**

- **Data vs logic separation.** All detection rules (permissions, regex patterns, SBP rules, OWASP map) live in `modules/patterns/` as plain Python data. The analyzers in `modules/` *consume* this data. Updating a rule means editing one file, no logic change.
- **Single orchestrator.** `analyzer.py` is the only module that knows the phase order. Phases never call each other directly. This makes the end-to-end flow a single readable function — defensible in viva ("walk me through what happens when I upload an APK").
- **Thin Flask layer.** `app.py` only handles HTTP. It validates input, calls the orchestrator, and renders templates. Zero analysis logic in routes.
- **DB access centralized.** All SQL lives in `db_manager.py`. No raw SQL strings in analyzers. Makes schema changes a one-file edit.

---

## 2. Tech stack version table

| Component | Version | Source | External? |
|---|---|---|---|
| Python | ≥3.11, <3.13 | python.org | — |
| Flask | ≥3.0.0, <4.0 | pip | — |
| Werkzeug | ≥3.0.0 (Flask dep) | pip | — |
| Jinja2 | ≥3.1.0 (Flask dep) | pip | — |
| PyAXMLParser | ≥0.3.27 | pip | — |
| ReportLab | ≥4.0.0 | pip | — |
| pytest | ≥8.0.0 | pip | Dev only |
| pytest-cov | ≥4.1.0 | pip | Dev only |
| Jadx | ≥1.5.0 | github.com/skylot/jadx releases | Yes (external binary) |
| ADB (platform-tools) | ≥35.0.0 | Android SDK | Yes (external binary) |
| Android Emulator | ≥35.0.0 | Android Studio | Yes (for dynamic analysis only) |

**Pinning policy:** `requirements.txt` uses `>=X.Y.Z,<X+1.0` constraints. This allows patch upgrades but locks major versions to prevent breaking changes.

---

## 3. Application routes (Flask)

| Method | Path | Purpose | Request | Response |
|---|---|---|---|---|
| GET | `/` | Home / upload page | — | HTML (`index.html`) |
| POST | `/upload` | Receive APK, kick off analysis | `multipart/form-data`: `apk_file`, `dynamic_enabled` (bool), `sbp_enabled` (bool), `educational_enabled` (bool) | 302 redirect → `/analysis/<id>` |
| GET | `/analysis/<analysis_id>` | Result page (tabbed) | — | HTML (`result.html`) |
| GET | `/analysis/<analysis_id>/report.pdf` | Download PDF report | — | `application/pdf` |
| GET | `/dashboard` | Analysis history | — | HTML (`dashboard.html`) |
| POST | `/analysis/<analysis_id>/delete` | Delete an analysis | — | 302 redirect → `/dashboard` |
| GET | `/api/analysis/<analysis_id>/status` | Polling endpoint for progress UI | — | `application/json`: `{status, current_phase, progress_pct}` |
| GET | `/api/finding/<finding_id>/educational` | Educational content for a finding (XHR) | — | `application/json`: `{vulnerable_snippet, fixed_snippet, explanation}` |
| GET | `/health` | Health check — verifies Jadx, ADB, emulator | — | `application/json`: `{python_ok, jadx_ok, adb_ok, emulator_ok}` |

**Notes on routes:**

- **`POST /upload`** runs synchronously through validation + APK hashing + DB row creation, then spawns a daemon thread for the slow analysis work. Returns immediately with the analysis_id so the user doesn't see a long blocking request.
- **`GET /analysis/<id>` while analysis is running** renders a "running" view that uses `status_poller.js` to call `/api/analysis/<id>/status` every 2 seconds until status flips to `completed`. Then the page re-renders with full results.
- **`POST /analysis/<id>/delete`** is `POST` not `DELETE` because vanilla HTML forms can't issue DELETE without JavaScript — and we want this to work without JS for accessibility.

---

## 4. Database schema (SQLite)

### Table: `analyses`
The master record. One row per analysis run.

```sql
CREATE TABLE analyses (
    id                     TEXT PRIMARY KEY,          -- UUID
    apk_filename           TEXT NOT NULL,             -- original uploaded filename
    apk_path               TEXT NOT NULL,             -- path under uploads/
    apk_hash_sha256        TEXT NOT NULL,             -- forensic integrity hash
    apk_size_bytes         INTEGER NOT NULL,
    package_name           TEXT,                      -- extracted from manifest (may be NULL during phase 1)
    app_name               TEXT,                      -- extracted from manifest
    version_name           TEXT,
    version_code           INTEGER,
    target_sdk             INTEGER,
    min_sdk                INTEGER,
    started_at             TIMESTAMP NOT NULL,
    completed_at           TIMESTAMP,                 -- NULL while running
    status                 TEXT NOT NULL,             -- 'running' | 'completed' | 'failed'
    current_phase          INTEGER,                   -- 2..7, NULL when complete
    progress_pct           INTEGER DEFAULT 0,
    error_message          TEXT,                      -- set if status='failed'
    dynamic_enabled        BOOLEAN NOT NULL,
    sbp_enabled            BOOLEAN NOT NULL,
    educational_enabled    BOOLEAN NOT NULL,
    risk_score             INTEGER,                   -- 0..100, computed in phase 5
    risk_classification    TEXT,                      -- 'LOW' | 'MEDIUM' | 'HIGH'
    pdf_path               TEXT,                      -- path under reports/, NULL until phase 6 done
    tool_version           TEXT NOT NULL              -- e.g., "SecureAPK 1.0.0"
);
CREATE INDEX idx_analyses_started_at ON analyses(started_at DESC);
CREATE INDEX idx_analyses_status ON analyses(status);
```

### Table: `findings`
One row per detected vulnerability. Covers manifest, source, dynamic, and SBP findings.

```sql
CREATE TABLE findings (
    id                  TEXT PRIMARY KEY,             -- UUID
    analysis_id         TEXT NOT NULL,
    phase               INTEGER NOT NULL,             -- 2 | 3 | 4 | 7
    category            TEXT NOT NULL,                -- e.g., "Hardcoded Secrets"
    severity            TEXT NOT NULL,                -- 'HIGH' | 'MEDIUM' | 'LOW'
    title               TEXT NOT NULL,                -- e.g., "Hardcoded API Key Detected"
    description         TEXT NOT NULL,
    file_location       TEXT,                         -- e.g., "com/app/Network.java" (NULL for manifest findings)
    line_number         INTEGER,
    code_snippet        TEXT,                         -- the offending code, NULL if not applicable
    owasp_id            TEXT,                         -- e.g., "M1" (Improper Credential Usage)
    cwe_id              TEXT,                         -- e.g., "CWE-798"
    pattern_id          TEXT,                         -- internal id, links to patterns/vuln_patterns.py
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
CREATE INDEX idx_findings_analysis ON findings(analysis_id);
CREATE INDEX idx_findings_severity ON findings(analysis_id, severity);
```

### Table: `permissions`
All permissions declared in the APK manifest.

```sql
CREATE TABLE permissions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL,
    permission_name TEXT NOT NULL,
    is_dangerous    BOOLEAN NOT NULL,
    severity        TEXT,                             -- 'HIGH'|'MEDIUM'|'LOW', NULL if not dangerous
    description     TEXT,                             -- why this permission is dangerous
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
CREATE INDEX idx_permissions_analysis ON permissions(analysis_id);
```

### Table: `exported_components`
Exported Activities, Services, Receivers, Providers from the manifest.

```sql
CREATE TABLE exported_components (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL,
    component_type  TEXT NOT NULL,                    -- 'activity'|'service'|'receiver'|'provider'
    component_name  TEXT NOT NULL,
    is_protected    BOOLEAN NOT NULL,                 -- TRUE if has permission attribute
    permission_attr TEXT,                             -- the permission name if protected
    is_dangerous    BOOLEAN NOT NULL,                 -- TRUE if exported AND unprotected
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
CREATE INDEX idx_exported_analysis ON exported_components(analysis_id);
```

### Table: `runtime_events`
Findings from dynamic analysis (Phase 4).

```sql
CREATE TABLE runtime_events (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id        TEXT NOT NULL,
    event_category     TEXT NOT NULL,                 -- one of 10 categories (see patterns/runtime_events.py)
    event_subtype      TEXT,                          -- finer-grained classification
    log_line           TEXT,                          -- the actual logcat line that triggered detection
    timestamp_in_session INTEGER,                     -- seconds since analysis start
    severity           TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
CREATE INDEX idx_runtime_analysis ON runtime_events(analysis_id);
```

### Table: `sbp_findings`
Pakistan State Bank cybersecurity compliance findings.

```sql
CREATE TABLE sbp_findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id         TEXT NOT NULL,
    sbp_rule_id         TEXT NOT NULL,                -- e.g., "SBP-CSF-3.2.1"
    rule_name           TEXT NOT NULL,
    compliance_status   TEXT NOT NULL,                -- 'COMPLIANT' | 'NON_COMPLIANT' | 'NOT_APPLICABLE'
    severity            TEXT,                         -- 'HIGH'|'MEDIUM'|'LOW' if non-compliant
    evidence            TEXT,                         -- what triggered the determination
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
CREATE INDEX idx_sbp_analysis ON sbp_findings(analysis_id);
```

### Table: `audit_log`
Forensic chain-of-custody. Every state change in an analysis is logged here.

```sql
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL,
    action          TEXT NOT NULL,                    -- e.g., 'analysis_started', 'phase_2_completed'
    actor           TEXT NOT NULL DEFAULT 'system',   -- 'system' for automated, 'user:<name>' otherwise
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details         TEXT,                             -- JSON or free text
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);
CREATE INDEX idx_audit_analysis ON audit_log(analysis_id, timestamp);
```

**Total: 7 tables.** Modest normalization — enough to demonstrate database design skill in viva without being overengineered for a single-user app.

---

## 5. UI / component map

```
Home page (/)
├── Header (logo "SecureAPK" left; nav right: Analyze [active] | Dashboard)
├── Hero section
│   ├── Monospace badge ("Final Year Project — LGU Digital Forensics & Cyber Security")
│   ├── Two-line gradient title ("Hybrid Android" / "Security Analysis" in cyan→blue gradient)
│   └── Muted description paragraph
├── Pipeline strip (5 step cards joined by → arrows)
│   └── APK Upload → Manifest Analysis → Code Scanning → Runtime Monitor → Risk Report
│       (each: icon + monospace label)
├── Upload card ("Upload APK for Analysis")
│   ├── Drag-and-drop zone (box icon, "Drag & drop your APK file here", "or click to browse — max 100 MB")
│   ├── Selected APK preview (filename, size)
│   ├── CSRF hidden field (added Phase 12)
│   ├── Options panel (three toggles, styled identically)
│   │   ├── ☐ Enable Dynamic Analysis (requires Android emulator via ADB)
│   │   │   └── ADB status indicator (Phase 12): inline banner below toggle showing
│   │   │       emulator availability. Fetched from /api/health/adb on toggle activation.
│   │   │       Warning state: "⚠ No emulator detected — dynamic analysis will be skipped."
│   │   │       OK state: "✓ Emulator detected: <serial>"
│   │   ├── ☐ Enable SBP Banking Compliance Check
│   │   └── ☐ Enable Educational Mode
│   └── [Start Analysis →] primary button (full width, blue; disabled until a file is selected)
│       └── Loading state (Phase 12): on submit, button shows spinner + "Uploading…", prevents double-submit
├── Feature cards (4-column grid)
│   ├── Manifest Inspection — permissions, exported components, cleartext config, debuggable flags
│   ├── Source Code Scanning — Jadx decompile, hardcoded secrets, weak crypto, 34 patterns
│   ├── Runtime Monitoring — ADB install + execute, logcat, network, runtime events
│   └── Risk Scoring — weighted severity model, Low/Medium/High, OWASP + CWE refs
└── Footer (two-line brand footer, year from config)

NOTE: the three toggles are non-negotiable. The visual mockups showed only the Dynamic
toggle, but SBP (Phase 7) and Educational (Phase 8) are core differentiators and MUST
remain in the options panel, styled identically to the Dynamic toggle.

Analysis Running view (/analysis/<id> while status='running')
├── Header (analysis id, app name placeholder)
├── Multi-step progress indicator (Phase 12 enhancement)
│   ├── Phase icons: Manifest → Source → Dynamic → SBP → Risk → Report
│   ├── Active phase highlighted with pulse animation
│   ├── Completed phases show checkmark
│   └── Conditional phases (Dynamic, SBP) shown dimmed if not enabled
├── Progress bar (0-100%)
├── Currently running phase label
└── (Auto-redirects to Result view when status='completed')

Result page (/analysis/<id> when status='completed')
├── Header (new chrome: logo + nav, brand footer, gradient/monospace accents)
│   ├── App name + package name
│   ├── APK hash (SHA-256, monospace, copyable)
│   ├── Risk badge (LOW/MEDIUM/HIGH pill with score)
│   └── [⬇ Download PDF Report] button
├── Tabs
│   ├── Manifest Analysis
│   │   ├── Metadata card (version, SDK levels)
│   │   ├── Insecure flags section (debuggable, cleartext, backup)
│   │   ├── Exported components table
│   │   └── Findings list (uses _partials/finding_card.html)
│   ├── Source Code
│   │   └── Findings grouped by category, each card optionally expandable in Educational Mode
│   ├── Dynamic Analysis (only if dynamic_enabled)
│   │   ├── Status banner (success / no emulator / partial)
│   │   │   └── Skip banner (Phase 12): prominent info-banner with setup instructions
│   │   │       and "Re-analyze" link when status=skipped_no_emulator. Visual distinction
│   │   │       between "not enabled" (neutral) and "enabled but skipped" (warning).
│   │   ├── Runtime events list
│   │   └── Findings list
│   ├── Risk Details
│   │   ├── Score breakdown by phase
│   │   ├── Top critical issues
│   │   └── OWASP MTW10 + CWE mapping table
│   ├── Permissions
│   │   └── All requested permissions with danger indicators
│   └── SBP Compliance (only if sbp_enabled)
│       ├── Compliance summary (X compliant, Y non-compliant of N rules)
│       └── Per-rule status with evidence
└── Footer (brand footer + analysis metadata: started, completed, tool version)

Dashboard (/dashboard)
├── Header (logo + nav; "Dashboard" active)
├── Title row ("Analysis Dashboard" heading + [+ New Analysis] blue button, right-aligned)
├── Analyses table
│   ├── Columns: ID (monospace, cyan, links to result) | APK File | Risk Level (pill badge)
│   │            | Score (NN/100) | Vulnerabilities | Date (YYYY-MM-DD) | Actions
│   ├── Actions per row: [View] (blue) [PDF] (green) [Del] (red)
│   └── Row hover highlights to surface-elevated
└── Footer (brand footer)

Finding card (reusable, used inside Source Code / SBP tabs)
├── Severity badge (HIGH/MEDIUM/LOW with color)
├── Title
├── Category
├── File location + line number (if applicable)
├── Code snippet (monospace)
├── Description
├── OWASP + CWE refs
└── [▾ Show Educational Detail] button (only if educational_enabled)
    └── Expanded state shows:
        ├── Vulnerable code (with red highlight)
        ├── Fixed code (with green highlight)
        └── Plain-English "Why this matters" explanation
```

> **Design reference:** the home page and dashboard visual design is locked to the approved mockups (hero + pipeline + feature cards; polished dashboard table with colored action buttons). See CLAUDE.md §5 for the exact color, typography, and component specs. The result page retains its tab structure from Phases 2–8 but adopts the new header, footer, fonts, and accent treatment for consistency.

---

## 6. Data shapes (the contracts modules pass between each other)

The orchestrator and DB layer rely on these dict shapes. They are the de-facto API between modules.

### `Finding` shape
```python
{
    "id": "uuid-string",
    "phase": 2 | 3 | 4 | 7,
    "category": "Hardcoded Secrets",
    "severity": "HIGH" | "MEDIUM" | "LOW",
    "title": "Hardcoded API Key Detected",
    "description": "An API key was found embedded directly in source code. ...",
    "file_location": "com/example/network/ApiClient.java" | None,
    "line_number": 42 | None,
    "code_snippet": "String apiKey = \"AIza...\";" | None,
    "owasp_id": "M1",       # OWASP Mobile Top 10 (2024) category id
    "cwe_id": "CWE-798",
    "pattern_id": "HARDCODED_GOOGLE_API_KEY",   # links back to patterns/vuln_patterns.py
}
```

### `ManifestAnalysisResult` shape (returned by `manifest_analyzer.analyze`)
```python
{
    "package_name": "com.example.app",
    "app_name": "Example App",
    "version_name": "1.0.0",
    "version_code": 100,
    "target_sdk": 33,
    "min_sdk": 21,
    "insecure_flags": {
        "uses_cleartext_traffic": True,
        "debuggable": False,
        "allow_backup": True,
        "network_security_config": None,
    },
    "permissions": [
        {"name": "android.permission.READ_SMS", "is_dangerous": True, "severity": "HIGH", "description": "..."},
        ...
    ],
    "exported_components": [
        {"type": "activity", "name": ".MainActivity", "is_protected": False, "permission_attr": None, "is_dangerous": False},
        ...
    ],
    "findings": [Finding, ...],
    "parser_used": "pyaxmlparser" | "aapt" | "dex_strings",   # which fallback level activated
}
```

### `SourceAnalysisResult` shape (returned by `source_analyzer.analyze`)
```python
{
    "decompiled": True | False,
    "decompiler_used": "jadx" | "dex_strings",
    "files_scanned": 247,
    "findings": [Finding, ...],
    "categories_triggered": ["Hardcoded Secrets", "Insecure Communication", ...],
}
```

### `DynamicAnalysisResult` shape (returned by `dynamic_analyzer.analyze`)
```python
{
    "status": "completed" | "skipped_no_emulator" | "skipped_install_failed" | "partial",
    "status_message": "Analysis completed successfully" | "No emulator detected. Setup: ...",
    "emulator_id": "emulator-5554" | None,
    "logcat_duration_seconds": 30,
    "events": [
        {"category": "Cleartext HTTP", "subtype": "outbound_http_request", "log_line": "...", "timestamp_in_session": 4, "severity": "HIGH"},
        ...
    ],
    "findings": [Finding, ...],
}
```

### `RiskAssessment` shape (returned by `risk_engine.compute`)
```python
{
    "raw_score": 187.5,
    "normalized_score": 78,          # 0-100
    "classification": "HIGH",        # 'LOW' (0-30) | 'MEDIUM' (31-70) | 'HIGH' (71-100)
    "breakdown_by_phase": {
        "manifest": 25,
        "source": 38,
        "dynamic": 15,
        "sbp": 0,
    },
    "top_issues": [Finding, ...],    # top 5 by severity*weight
    "owasp_categories_triggered": ["M1", "M5", "M9"],
    "cwes_triggered": ["CWE-798", "CWE-327", "CWE-319"],
}
```

---

## 7. Orchestrator design (`modules/analyzer.py`)

The orchestrator is the **only** module that knows the full phase sequence. Its job is to coordinate phases, write findings to the DB, and update audit log entries.

```python
# Pseudocode for analyzer.run_analysis()

def run_analysis(analysis_id: str, apk_path: str, options: AnalysisOptions) -> None:
    """
    Runs the full analysis pipeline. Called in a daemon thread from app.py.
    Updates the DB row for analysis_id as it progresses.
    """
    try:
        forensic.audit("analysis_started", analysis_id, details=options.to_dict())
        forensic.audit("hash_verified", analysis_id, details={"sha256": compute_sha256(apk_path)})

        # Phase 2: Manifest
        db.set_current_phase(analysis_id, 2)
        manifest = manifest_analyzer.analyze(apk_path)
        db.save_manifest_metadata(analysis_id, manifest)
        db.save_permissions(analysis_id, manifest.permissions)
        db.save_exported_components(analysis_id, manifest.exported_components)
        db.save_findings(analysis_id, manifest.findings)
        forensic.audit("phase_2_completed", analysis_id, details={"findings": len(manifest.findings)})
        db.set_progress(analysis_id, 25)

        # Phase 3: Source code
        db.set_current_phase(analysis_id, 3)
        source = source_analyzer.analyze(apk_path)
        db.save_findings(analysis_id, source.findings)
        forensic.audit("phase_3_completed", analysis_id, details={"findings": len(source.findings), "files_scanned": source.files_scanned})
        db.set_progress(analysis_id, 50)

        # Phase 4: Dynamic (optional)
        if options.dynamic_enabled:
            db.set_current_phase(analysis_id, 4)
            dynamic = dynamic_analyzer.analyze(apk_path, manifest.package_name)
            db.save_runtime_events(analysis_id, dynamic.events)
            db.save_findings(analysis_id, dynamic.findings)
            forensic.audit("phase_4_completed", analysis_id, details={"status": dynamic.status})
        db.set_progress(analysis_id, 70)

        # Phase 7: SBP (optional, runs before risk scoring)
        if options.sbp_enabled:
            db.set_current_phase(analysis_id, 7)
            sbp = sbp_compliance.analyze(apk_path, manifest, source)
            db.save_sbp_findings(analysis_id, sbp.findings)
            forensic.audit("phase_7_completed", analysis_id, details={"non_compliant": sbp.non_compliant_count})
        db.set_progress(analysis_id, 80)

        # Phase 5: Risk scoring
        db.set_current_phase(analysis_id, 5)
        risk = risk_engine.compute(analysis_id)
        db.save_risk(analysis_id, risk)
        forensic.audit("phase_5_completed", analysis_id, details={"score": risk.normalized_score, "classification": risk.classification})
        db.set_progress(analysis_id, 90)

        # Phase 6: Report
        db.set_current_phase(analysis_id, 6)
        pdf_path = report_generator.generate(analysis_id)
        db.set_pdf_path(analysis_id, pdf_path)
        forensic.audit("phase_6_completed", analysis_id, details={"pdf": pdf_path})

        db.mark_completed(analysis_id)
        forensic.audit("analysis_completed", analysis_id)

    except Exception as e:
        db.mark_failed(analysis_id, str(e))
        forensic.audit("analysis_failed", analysis_id, details={"error": str(e)})
        raise
```

**Why this design:**
- The orchestrator is the *only* place where the phase order is encoded. Every other module is a pure function of its inputs.
- Failures in any phase mark the analysis as `failed` but preserve all partial findings already saved. Nothing is lost.
- The audit log captures every state change — directly supports forensic chain-of-custody.

---

## 8. Concurrency model

**Decision:** Run analyses in a Python daemon thread spawned by the `/upload` route. No external task queue.

```python
# In app.py
@app.route("/upload", methods=["POST"])
def upload():
    # ... validation, save APK, compute hash, create DB row ...
    threading.Thread(
        target=analyzer.run_analysis,
        args=(analysis_id, apk_path, options),
        daemon=True,
    ).start()
    return redirect(url_for("view_analysis", analysis_id=analysis_id))
```

**Why threading and not Celery/Redis:**
- Single-user local app. No need for distributed task scheduling.
- Zero infrastructure overhead — no Redis to install, no worker process to manage.
- Threading is sufficient because analysis is I/O-bound (subprocess calls to Jadx and ADB), not CPU-bound — the GIL is not a bottleneck.

**Status polling:** `status_poller.js` calls `GET /api/analysis/<id>/status` every 2 seconds while the page is in the "running" state. The endpoint reads `current_phase` and `progress_pct` from the DB.

**Concurrent uploads:** Multiple analyses can run in parallel. SQLite handles concurrent writes adequately for this workload (writes are serialized; reads aren't blocked). Dynamic analysis cannot run concurrently because there's only one emulator — `dynamic_analyzer.analyze` acquires a module-level threading.Lock() before talking to ADB.

---

## 9. Pattern data structure (`modules/patterns/`)

Pattern files are pure Python data — lists/dicts with no logic. The analyzers import and consume them.

### `patterns/permissions.py` (37 entries)
```python
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": {
        "severity": "HIGH",
        "description": "Allows reading SMS messages. High privacy risk.",
        "owasp_id": "M3",
        "cwe_id": "CWE-200",
    },
    # ... 36 more
}
```

### `patterns/vuln_patterns.py` (30+ entries, 9 categories)
```python
VULN_PATTERNS = [
    {
        "id": "HARDCODED_GOOGLE_API_KEY",
        "category": "Hardcoded Secrets",
        "severity": "HIGH",
        "regex": r'AIza[0-9A-Za-z\-_]{35}',
        "title": "Hardcoded Google API Key",
        "description": "A Google API key was embedded in the source. ...",
        "owasp_id": "M1",
        "cwe_id": "CWE-798",
        "remediation": {
            "vulnerable_snippet": 'String apiKey = "AIzaSyB...";',
            "fixed_snippet": 'String apiKey = BuildConfig.GOOGLE_API_KEY;\n// In gradle: buildConfigField "String", "GOOGLE_API_KEY", "\\"${System.getenv(\'GOOGLE_API_KEY\')}\\""',
            "explanation": "API keys embedded in source code are visible to anyone who decompiles your APK. They should be loaded from build configuration or secure storage at runtime."
        }
    },
    # ... 29+ more across 9 categories
]
```

**The 9 categories:**
1. Hardcoded Secrets
2. Insecure Communication
3. Weak Cryptography
4. Insecure Data Storage
5. Information Leakage (logs)
6. WebView Security
7. Code Execution
8. IPC Security
9. SSL/TLS Validation Bypass

### `patterns/runtime_events.py` (10 categories)
```python
RUNTIME_EVENT_CATEGORIES = [
    {
        "id": "CLEARTEXT_HTTP",
        "name": "Cleartext HTTP Communication",
        "severity": "HIGH",
        "logcat_patterns": [r"http://[^\s]+", r"CleartextTraffic"],
        "description": "App made unencrypted HTTP request",
    },
    {"id": "CREDENTIAL_LOG_EXPOSURE", "name": "Credential Exposure in Logs", ...},
    {"id": "SSL_VALIDATION_EXCEPTION", "name": "SSL Certificate Validation Exception", ...},
    {"id": "INSECURE_NETWORK_OP", "name": "Insecure Network Operation", ...},
    {"id": "IMPLICIT_INTENT_IPC", "name": "IPC via Implicit Intent", ...},
    {"id": "RUNTIME_PERMISSION_DENIAL", "name": "Runtime Permission Denial", ...},
    {"id": "WORLD_READABLE_FILE_ACCESS", "name": "Suspicious File System Access", ...},
    {"id": "COMMAND_EXECUTION", "name": "Command Execution", ...},
    {"id": "REFLECTIVE_INVOCATION", "name": "Reflective Method Invocation", ...},
    {"id": "SECURITY_EXCEPTION_CRASH", "name": "Security-Sensitive Crash", ...},
]
```

### `patterns/sbp_rules.py` (Pakistan banking compliance)
```python
SBP_RULES = [
    {
        "id": "SBP-CSF-3.2.1",
        "name": "All network communication must use TLS 1.2 or higher",
        "category": "Network Security",
        "severity": "HIGH",
        "check": "no_cleartext_traffic AND tls_version >= 1.2",
        "evidence_source": "manifest+source",
    },
    {
        "id": "SBP-CSF-3.4.7",
        "name": "Sensitive data must not be logged",
        # ...
    },
    # ... full rule set
]
```

### `patterns/owasp_cwe_map.py`
```python
OWASP_MTW10_2024 = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}

CATEGORY_TO_OWASP = {
    "Hardcoded Secrets": "M1",
    "Insecure Communication": "M5",
    "Weak Cryptography": "M10",
    "Insecure Data Storage": "M9",
    # ...
}
```

---

## 10. Fallback chains (robustness contracts)

Each phase has a documented degradation strategy when its primary tool fails. These are non-negotiable.

### Manifest analysis fallback chain
1. **Primary:** `PyAXMLParser` parses the binary `AndroidManifest.xml` directly.
2. **Fallback 1:** If PyAXMLParser raises any exception, shell out to `aapt dump xmltree <apk> AndroidManifest.xml` and parse its text output with regex.
3. **Fallback 2:** If `aapt` is not installed or fails, extract printable strings from the raw manifest binary and pattern-match permission names and package name. Returns reduced metadata but never fails.

### Source code analysis fallback chain
1. **Primary:** `jadx --no-res --output-dir <tmpdir> <apk>` produces Java source. Walk and regex-scan.
2. **Fallback:** If `jadx` is not installed or exits non-zero, extract printable strings from `classes*.dex` files in the APK ZIP and pattern-match against the same regexes. Coverage is reduced (no file/line numbers, no code context), but findings are still produced.

### Dynamic analysis fallback chain
1. **Primary:** `adb devices` shows a running emulator. Full install → launch → monkey → logcat → uninstall pipeline.
2. **Fallback:** If no emulator detected OR `adb` not installed, return a `DynamicAnalysisResult` with `status="skipped_no_emulator"` and a clear message instructing the user how to start an emulator. Zero findings, zero crashes.
3. **Partial path:** If install succeeds but launch or monkey fails, the phase returns whatever events were captured up to that point with `status="partial"`.

---

## 11. The three differentiators — technical details

### 11.1 Forensic-grade reporting (Phase 6 baseline + Phase 11 court-admissibility)

The forensic report is the project's primary differentiator and must be court-admissible — meaning it contains the elements a digital forensic report would include under **ISO/IEC 27037:2012** (Guidelines for identification, collection, acquisition and preservation of digital evidence). Phase 6 shipped the baseline; Phase 11 brings it to court-admissibility.

**Required cover-page blocks (in order):**

1. **Tool identification** — name, version (`SecureAPK v1.0.0`), one-line description, report generation timestamp in ISO 8601 with explicit timezone (e.g. `2026-05-31T14:41:50+05:00 (PKT)`)
2. **Case identification** — analysis ID treated as case number, analyst name (from upload-form field, default `Anonymous Analyst`), institution (`Lahore Garrison University, Department of Criminology`)
3. **Evidence identification** — APK filename, file size in bytes, **SHA-256** (prominent, monospace — primary integrity proof), SHA-1 (defensive), MD5 (legacy compatibility), package name, version name, version code
4. **Software environment** — host OS + version, Python version, Jadx version (or "not installed"), ADB version (or "not used"), SecureAPK version
5. **Statement of Methodology** — short paragraph describing the six-phase methodology, citing ISO/IEC 27037 as the governing framework

**Phase 12 additions — new PDF sections (in document order):**

1. **Table of Contents** (after cover page) — ReportLab `TableOfContents` flowable listing all major sections with page numbers
2. **Executive Summary** (after TOC, 1 page) — risk classification badge, finding counts by severity (HIGH/MEDIUM/LOW), top 3 issues, OWASP categories triggered, one-sentence recommendation, severity distribution bar chart (ReportLab `Drawing` with colored rectangles — no external dependencies)
3. **Scope & Limitations** (after methodology) — what was analyzed, what was NOT (obfuscated code, native .so, server-side APIs), tool limitations (no Frida, emulator-only dynamic)
4. **Legal Disclaimer** (cover page footer) — "This report is generated for educational and authorized security assessment purposes only."

**Body sections (with Phase 12 enhancements):**
- **Section numbering** — all major sections prefixed: 1. Risk Summary, 2. Manifest Analysis, 3. Source Code Analysis, etc. Subsections: 1.1, 1.2, etc.
- **Findings Summary Tables** — at the start of each findings section: Category | Count | Highest Severity
- Risk summary
- Phase 2 / 3 / 4 / 7 findings (each phase heading carries a UTC timestamp of when that phase completed)
- OWASP MTW10 + CWE references
- (Educational expansions, when enabled)
- **Conclusion & Recommendations** (after findings, before appendices) — total findings, classification, top 3 actionable recommendations, analysis scope statement

**Required appendices (in order):**

1. **Chain of Custody** — full chronological list of every entry in the `audit_log` table for this analysis. Each row: timestamp (ISO 8601 with TZ), actor, action, details. This is the chain-of-custody section.
2. **Verification of Evidence Integrity** — explicit step-by-step instructions for a third party to verify the analyzed APK hasn't been altered: locate the original APK file, run `sha256sum` (or equivalent on the host OS), compare to the value printed in the Evidence Identification block, conclude integrity preserved/compromised.

**Document-level guarantees:**

- All timestamps are **ISO 8601 with explicit timezone offset** — never local time without TZ.
- **Page numbers** in every footer: `Page X of Y`.
- **Generation stamp** in every footer: `Generated by SecureAPK v1.0.0 — <ISO timestamp>`.
- **Byte-identical regeneration** preserved from Phase 6 (D-15) — apart from the generation timestamp in the footer, two PDFs of the same analysis are byte-equal.
- **Hash grep-ability** preserved from Phase 6 (D-14) — `pageCompression=0` keeps the SHA-256 plaintext-discoverable in the PDF bytes.
- **No digital signatures** — out of scope for an academic FYP (no PKI). Integrity rests on the visible SHA-256, the byte-identical regeneration property, and the chain-of-custody appendix.

**Schema change required:** the `analyses` table gains a nullable `analyst_name TEXT` column. The upload form gets a single optional text input for the analyst's name, persisted to this column at upload time. Existing rows default to NULL (rendered as "Anonymous Analyst" in reports).

### 11.2 SBP banking compliance (`modules/sbp_compliance.py`)

**Banking app heuristic:** an APK is flagged as "likely banking/financial" if any of the following are true:
- Package name contains: `bank`, `pay`, `wallet`, `finance`, `cash`
- App name contains: `bank`, `pay`, `wallet`, `JazzCash`, `EasyPaisa`, `HBL`, `MCB`, `UBL`, etc.
- Permissions include `READ_SMS` AND `READ_CONTACTS` AND `INTERNET` (common combo for OTP-based banking)

If user explicitly toggles "Enable SBP Compliance Check," the heuristic is bypassed and rules run regardless.

**Each SBP rule** is checked against the existing static + (if enabled) dynamic findings — the SBP module does not re-parse the APK. It reads from the same `manifest`, `source`, and `dynamic` results the orchestrator already produced. This keeps SBP a thin compliance layer, not a parallel analyzer.

### 11.3 Educational mode (`modules/educational.py`)

**Design:** Each pattern in `patterns/vuln_patterns.py` includes a `remediation` dict with three keys: `vulnerable_snippet`, `fixed_snippet`, `explanation`. The `educational` module is a thin lookup layer — when the UI requests educational content for a specific finding, it returns the `remediation` dict from the matching pattern.

**Coverage:** Every regex pattern in `vuln_patterns.py` must have a `remediation` entry. Tests will enforce this — the test suite includes a check that no pattern lacks educational content.

**UI behavior:** When `educational_enabled=True`, finding cards on the result page get a "[▾ Show Educational Detail]" button. Clicking it expands the card to show the three subsections. Implementation is XHR fetching `GET /api/finding/<id>/educational` to keep the initial page load light.

---

## 12. Configuration (`config.py`)

```python
# config.py — All tunables in one place.

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Paths
DATABASE_PATH = BASE_DIR / "database" / "secureapk.db"
UPLOADS_PATH = BASE_DIR / "uploads"
REPORTS_PATH = BASE_DIR / "reports"

# External tools (None = use PATH lookup)
JADX_PATH = os.environ.get("SECUREAPK_JADX_PATH", None)
ADB_PATH = os.environ.get("SECUREAPK_ADB_PATH", None)
AAPT_PATH = os.environ.get("SECUREAPK_AAPT_PATH", None)

# Limits
MAX_UPLOAD_SIZE_MB = 100   # matches the "max 100 MB" shown on the upload card
ANALYSIS_TIMEOUT_SECONDS = 300
JADX_TIMEOUT_SECONDS = 180
DYNAMIC_LOGCAT_DURATION_SECONDS = 30
DYNAMIC_MONKEY_EVENT_COUNT = 50

# Risk scoring
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
RISK_THRESHOLDS = {"LOW_MAX": 30, "MEDIUM_MAX": 70}  # >70 = HIGH
SCORE_NORMALIZATION_DIVISOR = 200  # raw / 200 * 100 capped at 100

# Flask
HOST = os.environ.get("SECUREAPK_HOST", "127.0.0.1")
PORT = int(os.environ.get("SECUREAPK_PORT", "5000"))
DEBUG = os.environ.get("SECUREAPK_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("SECUREAPK_SECRET_KEY", "dev-only-secret-change-in-production")

# Tool metadata
TOOL_NAME = "SecureAPK"
TOOL_VERSION = "1.0.0"
```

**Environment variables (all optional):** `SECUREAPK_JADX_PATH`, `SECUREAPK_ADB_PATH`, `SECUREAPK_AAPT_PATH`, `SECUREAPK_HOST`, `SECUREAPK_PORT`, `SECUREAPK_DEBUG`, `SECUREAPK_SECRET_KEY`. None are required for local demo.

---

## 13. External dependencies — verification (`setup.py`)

`setup.py` is a one-time bootstrap script the user runs after `pip install`. It:

1. Verifies Python version ≥3.11.
2. Initializes the SQLite database (creates all 7 tables if not present).
3. Creates `uploads/`, `reports/`, `database/` directories.
4. Probes for `jadx` in PATH. If absent, prints install instructions but does NOT fail (fallback chain handles missing Jadx).
5. Probes for `adb` in PATH. If absent, prints instructions, doesn't fail.
6. Probes for running emulator via `adb devices`. Reports status.
7. Prints summary: "✓ Python ✓ DB ✓ Jadx ✓ ADB ⚠ No emulator running" — and exits 0.

The same probing logic is exposed at `GET /health` so users can verify mid-session.

---

## 14. Error handling philosophy

- **Internal errors never reach the user as a 500 page.** All exceptions in the analyzer are caught, logged to the audit log, and surfaced as `status='failed'` with an `error_message` on the analysis row. The result page renders the failure gracefully.
- **External tool failures are routed through fallback chains** (see section 10). Never assume Jadx is installed. Never assume an emulator is running.
- **Validation errors return 400 with a JSON body** for API endpoints, or re-render the upload page with an error banner for HTML routes.
- **Database errors are not retried.** If SQLite refuses a write, something is structurally wrong; better to fail loudly.
- **No silent failures.** Every catch block must either log or re-raise. No bare `except: pass`.

---

## 15. The 50+ tests — coverage plan

| Module | Test file | Test count target | Notes |
|---|---|---|---|
| `manifest_analyzer.py` | `test_manifest_analyzer.py` | 5 | |
| `source_analyzer.py` | `test_source_analyzer.py` | 5 | |
| `dynamic_analyzer.py` | `test_dynamic_analyzer.py` | 5 (mocked ADB) | +1 for monkey event count (Phase 12) |
| `risk_engine.py` | `test_risk_engine.py` | 4 | |
| `report_generator.py` | `test_report_generator.py` | 5 | +2 for TOC and executive summary (Phase 12) |
| `forensic.py` | `test_forensic.py` | 3 | |
| `sbp_compliance.py` | `test_sbp_compliance.py` | 3 | |
| `educational.py` | `test_educational.py` | 2 (incl. "every pattern has remediation") | |
| `db_manager.py` | `test_db_manager.py` | 3 | |
| `analyzer.py` | `test_orchestrator.py` | 2 (end-to-end with mocks) | |
| `app.py` | `test_app.py` | 3 | +2 for ADB health endpoint and CSRF (Phase 12), +1 for dashboard single query |
| **Total** | | **40 base + 6 Phase 12 = 46 current → 50+ after Phase 12** | |

Performance test: a separate benchmark run in `test_orchestrator.py` that asserts a small APK completes phases 2+3 in under 60 seconds.

**Phase 12 new tests:**
1. ADB health endpoint — mock `subprocess.run`, assert `/api/health/adb` returns correct JSON
2. Monkey event count — assert monkey command uses `config.DYNAMIC_MONKEY_EVENT_COUNT`
3. PDF Table of Contents — extract text from generated PDF, assert TOC present
4. PDF Executive Summary — assert executive summary contains risk classification and counts
5. CSRF token present — GET upload page, assert hidden CSRF field in HTML
6. Dashboard single query — mock DB, assert exactly 1 query for listing analyses

---

*This file is the technical reference. Any structural change requires explicit approval in the planning chat. Last updated: Phase 12 planning (UI component map §5, report format §11.1, test plan §15 updated).*
