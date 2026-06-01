# PHASES.md — SecureAPK Execution Roadmap

> **For Claude Code:** Read this AFTER `CLAUDE.md` and `ARCHITECTURE.md`. This file defines the sequence of work. Each phase is exactly one focused session. Do not expand a phase's scope mid-execution — if something seems missing, document it in `SCRATCHPAD.md` under `## Open questions` and surface it in the planning chat.

> **For Nayab:** This is the build order. Phases are sequential — no phase begins until the previous one is approved and merged. When a panel asks "how did you build this?", you walk them through this file phase by phase.

---

## Status tracker

Update the boxes as phases progress: `⬜` not started → `🔄` in progress → `✅` complete.

- ✅ **Phase 1** — Foundation
- ✅ **Phase 2** — Manifest Analyzer (proposal Phase 2)
- ✅ **Phase 3** — Source Code Analyzer (proposal Phase 3)
- ✅ **Phase 4** — Dynamic Analyzer (proposal Phase 4) — rebuilt from scratch
- ✅ **Phase 5** — Risk Engine + OWASP/CWE Mapping (proposal Phase 5)
- ✅ **Phase 6** — PDF Reports + Forensic Hashing (proposal Phase 6 + Feature 1)
- ✅ **Phase 7** — SBP Banking Compliance (Feature 2)
- ✅ **Phase 8** — Educational Mode (Feature 3)
- ✅ **Phase 9** — Testing & Polish
- ⬜ **Phase 10** — UI Redesign (post-v1.0.0 visual overhaul to the approved mockups)
- ⬜ **Phase 11** — Court-Admissible Forensic Report (expands Phase 6 PDF to ISO/IEC 27037 standard)

---

## Phase governance (apply to every phase)

These rules are global. They override anything that contradicts them in a specific phase.

1. **One phase = one Claude Code session = one branch.** Branch naming: `phase-N-short-description`.
2. **Push to that branch, never to `main`.** Open a PR at the end of the session.
3. **Update `SCRATCHPAD.md` before closing the session.** No exceptions.
4. **Acceptance criteria are gates.** A phase isn't done until every checkbox is verified.
5. **If scope is ambiguous, ask — don't guess.** Add an entry to `SCRATCHPAD.md` under `## Open questions` and stop.
6. **No phase begins until the previous PR is merged into `main`.** The framework prevents compounding errors.

---

## Phase 1 — Foundation

### Goal
A bootable Flask app with database, upload flow, dashboard, and health check — but no analysis logic yet. End-to-end vertical slice with placeholder analyzer.

### Branch
`phase-1-foundation`

### Files created
- `app.py` — Flask routes per ARCHITECTURE.md §3
- `config.py` — all tunables per ARCHITECTURE.md §12
- `setup.py` — bootstrap script per ARCHITECTURE.md §13
- `requirements.txt`
- `modules/__init__.py`
- `modules/db_manager.py` — all 7 tables + CRUD per ARCHITECTURE.md §4
- `modules/forensic.py` — `compute_sha256()`, `audit()` functions only (chain-of-custody PDF integration comes in Phase 6)
- `modules/analyzer.py` — orchestrator skeleton with placeholder phase calls that just log "phase X not implemented" and set status='completed'
- `templates/base.html` — common shell with nav and footer
- `templates/index.html` — upload form with options panel (the three toggles)
- `templates/result.html` — placeholder showing "Analysis ID, status, no findings yet"
- `templates/dashboard.html` — analyses table
- `templates/_partials/risk_badge.html` — placeholder badge
- `static/css/main.css` — dark theme using the design tokens from CLAUDE.md §5
- `static/css/result.css`
- `static/css/dashboard.css`
- `static/js/main.js` — drag-drop upload, toggle state
- `static/js/status_poller.js` — polling for analysis status
- `README.md` — basic setup and run instructions
- `tests/__init__.py`
- `tests/conftest.py` — DB fixture, temp directories
- `tests/test_db_manager.py` — 3 tests: schema creation, basic insert, foreign key cascade

### In scope
- Flask app boots and serves all routes listed in ARCHITECTURE.md §3 (some return placeholders)
- SQLite DB initializes with all 7 tables on first run
- Upload accepts an APK, validates size + extension, saves to `uploads/<analysis_id>.apk`
- SHA-256 computed at upload, saved to `analyses.apk_hash_sha256`
- Audit log entries created: `analysis_started` → `hash_verified` → `analysis_completed` (no real phases yet)
- `/health` endpoint reports Python/Jadx/ADB/emulator status
- Dashboard lists analyses, supports delete
- Dark theme renders correctly using the design tokens
- 3 tests pass

### Out of scope (do NOT do these in Phase 1)
- Any actual APK analysis logic
- `manifest_analyzer.py`, `source_analyzer.py`, `dynamic_analyzer.py` — these come in later phases
- PDF generation
- Educational mode UI
- SBP module
- Pattern data files (`modules/patterns/`)

### Task checklist
- [ ] Create folder structure exactly as ARCHITECTURE.md §1 specifies (empty `modules/patterns/` directory is fine for Phase 1)
- [ ] `requirements.txt` includes: `flask>=3.0,<4.0`, `pyaxmlparser>=0.3.27`, `reportlab>=4.0`, `pytest>=8.0`, `pytest-cov>=4.1` (some will be unused in Phase 1; that's OK)
- [ ] `setup.py` initializes DB, creates folders, probes external tools, exits 0
- [ ] `db_manager.py` provides typed functions: `create_analysis(...)`, `set_current_phase(...)`, `set_progress(...)`, `mark_completed(...)`, `mark_failed(...)`, `save_findings(...)`, `get_analysis(...)`, `list_analyses(...)`, `delete_analysis(...)`, `add_audit_entry(...)`
- [ ] `forensic.py` provides: `compute_sha256(filepath) -> str`, `audit(action, analysis_id, actor='system', details=None)`
- [ ] `analyzer.py` provides `run_analysis(analysis_id, apk_path, options)` that just logs phase placeholders and marks analysis completed — keeps the daemon thread pattern from ARCHITECTURE.md §8
- [ ] `app.py` implements all 9 routes from ARCHITECTURE.md §3
- [ ] Upload size enforced (`MAX_UPLOAD_SIZE_MB`)
- [ ] Upload validates `.apk` extension (no magic byte check yet — that's a Phase 2 nice-to-have)
- [ ] Result page polls status every 2 seconds while `status='running'`
- [ ] Dashboard supports delete (cascades to all child tables)
- [ ] Dark theme colors match CLAUDE.md §5 exactly
- [ ] Tests pass: `pytest tests/test_db_manager.py -v`

### Acceptance criteria
1. `python setup.py` runs successfully on a clean checkout
2. `python app.py` boots, serves on `127.0.0.1:5000`
3. Visiting `/` shows the upload page in dark theme
4. Uploading a `.apk` file creates an `analyses` row, saves the APK to `uploads/`, computes its SHA-256, and redirects to `/analysis/<id>`
5. `/analysis/<id>` shows "Analysis pending — analyzers not yet implemented" with the APK hash visible
6. After ~2 seconds, the placeholder `analyzer.run_analysis` marks the analysis `completed` and the result page refreshes
7. `/dashboard` shows the analysis with delete button working
8. `/health` returns valid JSON with all four flags
9. `pytest` exits 0 with at least 3 passing tests

### Done definition
PR opened from `phase-1-foundation` → `main` with all acceptance criteria verified. `SCRATCHPAD.md` updated with: what was built, any open questions, the live local URL.

---

## Phase 2 — Manifest Analyzer (proposal Phase 2)

### Goal
Implement static analysis of `AndroidManifest.xml` — extract metadata, detect dangerous permissions, identify exported components, flag insecure configurations.

### Branch
`phase-2-manifest-analyzer`

### Files created
- `modules/manifest_analyzer.py`
- `modules/patterns/__init__.py`
- `modules/patterns/permissions.py` — exactly **37 dangerous permissions** with severity, description, OWASP id, CWE id
- `modules/patterns/owasp_cwe_map.py` — initial OWASP MTW10 (2024) categories + `CATEGORY_TO_OWASP` dict (will expand in later phases)
- `tests/test_manifest_analyzer.py` — 5 tests

### Files modified
- `modules/analyzer.py` — replace Phase 2 placeholder with real call to `manifest_analyzer.analyze()`
- `templates/result.html` — populate the Manifest Analysis tab
- `templates/_partials/finding_card.html` — first real finding card implementation (no educational expansion yet — that's Phase 8)

### In scope
- Parse `AndroidManifest.xml` via PyAXMLParser (primary)
- Fallback chain per ARCHITECTURE.md §10 — `aapt` then raw DEX string extraction
- Extract: package_name, app_name, version_name, version_code, target_sdk, min_sdk
- Detect 37 dangerous permissions from `patterns/permissions.py`
- Detect exported activities/services/receivers/providers and whether they have permission attributes
- Detect insecure flags: `usesCleartextTraffic`, `debuggable`, `allowBackup`, missing `networkSecurityConfig`
- Findings written to DB via `db_manager.save_findings()`
- Result page renders the Manifest tab with metadata card, insecure flags section, exported components table, findings list

### Out of scope
- Source code scanning (Phase 3)
- Any UI for source/dynamic/SBP/educational tabs — show "not yet implemented" placeholders
- Risk scoring (Phase 5)
- PDF generation (Phase 6)

### Task checklist
- [ ] `patterns/permissions.py` defines `DANGEROUS_PERMISSIONS` dict with exactly 37 entries
- [ ] Each permission entry has: severity, description, owasp_id, cwe_id
- [ ] `manifest_analyzer.analyze(apk_path)` returns `ManifestAnalysisResult` shape per ARCHITECTURE.md §6
- [ ] Fallback chain implemented and tested
- [ ] `analyzer.py` saves manifest metadata, permissions, exported components, findings to DB
- [ ] Result page Manifest tab renders all four sections (metadata, insecure flags, exported components, findings)
- [ ] All 5 tests pass

### Acceptance criteria
1. Upload DIVA APK (or any known-vulnerable APK) — see populated package name, app name, version
2. Permissions list shows danger indicators for any dangerous perms requested
3. Exported components table lists components and flags unprotected exported ones
4. Insecure flags section shows which insecure flags are set
5. Findings list shows findings from the manifest analysis with severity badges
6. `parser_used` field shows which fallback level activated
7. `pytest tests/test_manifest_analyzer.py -v` exits 0

### Tests required (5)
1. Successful PyAXMLParser parse on a valid APK
2. Fallback to `aapt` when PyAXMLParser fails (simulate via mock)
3. Final fallback to DEX string extraction
4. Detection of `android:debuggable="true"`
5. Detection of unprotected exported component

### Done definition
PR opened. SCRATCHPAD updated with: number of findings produced on the DIVA test APK, parser_used value, any open questions.

---

## Phase 3 — Source Code Analyzer (proposal Phase 3)

### Goal
Decompile APK via Jadx, scan decompiled Java source against 30+ regex patterns across 9 categories.

### Branch
`phase-3-source-analyzer`

### Files created
- `modules/source_analyzer.py`
- `modules/patterns/vuln_patterns.py` — **30+ regex patterns across 9 categories** per ARCHITECTURE.md §9, each with full `remediation` dict (so Phase 8 has the content ready)
- `tests/test_source_analyzer.py` — 5 tests

### Files modified
- `modules/analyzer.py` — replace Phase 3 placeholder with real call
- `modules/patterns/owasp_cwe_map.py` — expand `CATEGORY_TO_OWASP` to cover all 9 source-code categories
- `templates/result.html` — populate the Source Code tab

### In scope
- Decompile APK via `jadx --no-res --output-dir <tmpdir>` with `JADX_TIMEOUT_SECONDS` from config
- Fallback: extract printable strings from `classes*.dex` and scan against same regexes
- Walk every `.java` file, scan each line against `VULN_PATTERNS`
- Capture: matched pattern_id, file path (relative), line number, code snippet (the matching line plus ±1 lines of context)
- Deduplicate: same pattern_id + same file → only report first occurrence (prevents flooding from patterns like "private static" on every class)
- Findings written to DB
- Source Code tab renders findings grouped by category

### Out of scope
- Dynamic analysis (Phase 4)
- SBP banking checks (Phase 7)
- Educational mode UI (Phase 8) — but `remediation` dicts MUST be present in pattern data, ready for Phase 8 consumption
- Any abstract syntax tree (AST) analysis — regex only per the literature review's stated approach

### Task checklist
- [ ] `patterns/vuln_patterns.py` defines `VULN_PATTERNS` list with at least 30 entries spanning all 9 categories
- [ ] **Every pattern has a complete `remediation` dict** with `vulnerable_snippet`, `fixed_snippet`, `explanation` — Phase 8 depends on this
- [ ] `source_analyzer.analyze(apk_path)` returns `SourceAnalysisResult` shape per ARCHITECTURE.md §6
- [ ] Jadx invocation respects `JADX_TIMEOUT_SECONDS`, kills process on timeout
- [ ] DEX string fallback works when Jadx is uninstalled (test by temporarily unsetting PATH)
- [ ] Per-pattern-per-file dedup is implemented
- [ ] Result page Source Code tab renders findings grouped by category with file/line info
- [ ] All 5 tests pass

### Acceptance criteria
1. Upload DIVA APK → see source code findings populating all 9 categories
2. Each finding shows file location and line number
3. Code snippets visible with monospace font
4. Categories triggered on a real vulnerable APK include at least: Hardcoded Secrets, Insecure Communication, Weak Cryptography
5. When Jadx not installed, falls back gracefully and still produces findings (fewer details)
6. `pytest tests/test_source_analyzer.py -v` exits 0
7. Total tests so far: 8+

### Tests required (5)
1. Successful Jadx decompilation
2. Detection of hardcoded Google API key pattern
3. Detection of `MessageDigest.getInstance("MD5")` weak crypto pattern
4. DEX string fallback when Jadx unavailable
5. Per-pattern-per-file deduplication works

### Done definition
PR opened. SCRATCHPAD updated with: total pattern count (must be ≥30), categories triggered on test APK, count of findings.

---

## Phase 4 — Dynamic Analyzer (proposal Phase 4) — REBUILT FROM SCRATCH

### Goal
Implement automated runtime analysis via ADB. Install APK in emulator, launch, capture logcat for 30 seconds, classify events into 10 categories, uninstall.

**This is the phase that was broken in the existing repo. We are not salvaging — we are rebuilding clean.**

### Branch
`phase-4-dynamic-analyzer`

### Files created
- `modules/dynamic_analyzer.py`
- `modules/patterns/runtime_events.py` — exactly **10 runtime event categories** per ARCHITECTURE.md §9
- `tests/test_dynamic_analyzer.py` — 4 tests (all using mocked ADB; we don't need a real emulator in tests)

### Files modified
- `modules/analyzer.py` — replace Phase 4 placeholder
- `templates/result.html` — populate the Dynamic Analysis tab with status banners

### In scope
- ADB workflow per ARCHITECTURE.md §10 fallback chain:
  1. `adb devices` to detect emulator
  2. `adb install -r -t <apk>` to install
  3. `adb shell monkey -p <package_name> -c android.intent.category.LAUNCHER 1` to launch
  4. Wait 3 seconds for app to settle
  5. Optional: `adb shell monkey -p <package_name> --throttle 500 50` to drive interactions
  6. Parallel: capture `adb logcat -v time` for `DYNAMIC_LOGCAT_DURATION_SECONDS` seconds
  7. `adb shell dumpsys package <package_name>` for granted permissions snapshot
  8. `adb uninstall <package_name>` to clean up
- Classify each logcat line against the 10 runtime event categories
- Module-level `threading.Lock` to serialize ADB access (per ARCHITECTURE.md §8)
- Graceful degradation when no emulator detected — return `status="skipped_no_emulator"` with clear instructions
- Result page Dynamic tab shows: status banner, runtime events list, findings list

### Out of scope
- Frida instrumentation, Xposed, or any non-ADB dynamic tool (hard rule from CLAUDE.md §6)
- Network packet capture via Wireshark or mitmproxy
- UI automation beyond the monkey tool
- Anything requiring a rooted emulator

### Task checklist
- [ ] `patterns/runtime_events.py` defines `RUNTIME_EVENT_CATEGORIES` list with exactly 10 entries
- [ ] Each category has: id, name, severity, logcat_patterns (list of regex), description
- [ ] `dynamic_analyzer.analyze(apk_path, package_name)` returns `DynamicAnalysisResult` shape per ARCHITECTURE.md §6
- [ ] All ADB subprocess calls use `subprocess.run(..., timeout=X, capture_output=True)` — no orphan processes
- [ ] Module-level threading lock prevents concurrent ADB calls
- [ ] `status="skipped_no_emulator"` is returned cleanly when `adb devices` shows nothing — no exception
- [ ] If install succeeds but launch fails → `status="partial"` with whatever was captured
- [ ] Logcat parser deduplicates similar events (e.g., 50 identical HTTP requests collapse to one event with `count=50`)
- [ ] Result page Dynamic tab renders status banner (green=ok, yellow=partial, red=skipped)
- [ ] `app.py` upload route only runs Phase 4 if `dynamic_enabled` in options
- [ ] All 4 tests pass (mocked subprocess for ADB)

### Acceptance criteria
1. With a running emulator: upload APK with Dynamic Analysis enabled → see runtime events captured + findings populated
2. Without emulator: see clear "No emulator detected — start one via Android Studio" message, NO crash, NO error toast
3. With `dynamic_enabled=False`: Dynamic tab shows "Dynamic analysis was not enabled for this scan"
4. Logcat capture respects `DYNAMIC_LOGCAT_DURATION_SECONDS` (no longer than configured)
5. APK is always uninstalled at the end, even if logcat capture fails partway
6. `pytest tests/test_dynamic_analyzer.py -v` exits 0
7. Total tests so far: 12+

### Tests required (4)
1. Successful end-to-end with mocked ADB returning canned logcat output
2. "No emulator" path returns `status="skipped_no_emulator"` with no exception
3. Install timeout returns `status="skipped_install_failed"`
4. Logcat parser correctly classifies a `CleartextTraffic` log line

### Done definition
PR opened. SCRATCHPAD updated with: status returned on real emulator test (if Nayab has emulator running locally), events captured count, any ADB command quirks discovered.

---

## Phase 5 — Risk Engine + OWASP/CWE Mapping (proposal Phase 5)

### Goal
Compute weighted risk score across all findings, classify as Low/Medium/High, build OWASP MTW10 + CWE summary tables.

### Branch
`phase-5-risk-engine`

### Files created
- `modules/risk_engine.py`
- `tests/test_risk_engine.py` — 4 tests

### Files modified
- `modules/patterns/owasp_cwe_map.py` — fill in any remaining mappings
- `modules/analyzer.py` — Phase 5 runs after detection phases complete
- `templates/result.html` — populate the Risk Details tab + show risk badge in header
- `templates/_partials/risk_badge.html` — finalize implementation with proper colors

### In scope
- Read all findings for an `analysis_id` from DB
- Apply per-finding score: `severity_weight × category_multiplier` using values from `config.py`
- Sum into `raw_score`, normalize to 0–100 via `raw_score / SCORE_NORMALIZATION_DIVISOR × 100` capped at 100
- Classify using `RISK_THRESHOLDS`: Low (0–30), Medium (31–70), High (71–100)
- Compute breakdown by phase (manifest/source/dynamic/sbp contributions)
- Identify top 5 findings by `weight × multiplier` for "Top Issues"
- Aggregate triggered OWASP MTW10 categories and CWE ids
- Save back to `analyses` row: `risk_score`, `risk_classification`
- Result page Risk Details tab renders all sections per ARCHITECTURE.md §5

### Out of scope
- PDF generation (Phase 6)
- Re-scoring on demand (e.g., a user adjusting weights) — the score is computed once
- CVSS or other external scoring frameworks

### Task checklist
- [ ] `risk_engine.compute(analysis_id)` returns `RiskAssessment` shape per ARCHITECTURE.md §6
- [ ] Uses `SEVERITY_WEIGHTS` and `CATEGORY_MULTIPLIERS` from `config.py`
- [ ] Normalization formula matches `config.SCORE_NORMALIZATION_DIVISOR`
- [ ] Risk classification thresholds match `config.RISK_THRESHOLDS`
- [ ] `breakdown_by_phase` correctly attributes score to each phase
- [ ] `top_issues` returns top 5 by impact score
- [ ] OWASP/CWE aggregation pulls from `owasp_cwe_map.CATEGORY_TO_OWASP`
- [ ] Risk badge in result.html header displays correct color (red/amber/green per CLAUDE.md §5)
- [ ] Risk Details tab renders breakdown bar chart (simple CSS bars, no JS chart lib)
- [ ] All 4 tests pass

### Acceptance criteria
1. Re-analyze DIVA APK — see risk_classification="HIGH" (it's intentionally vulnerable, score should be 70+)
2. Re-analyze a benign APK (e.g., a simple Hello World) — see Low or no findings
3. Risk badge color matches classification
4. Top issues list shows highest-impact findings
5. OWASP table shows triggered categories with their MTW10 names
6. `pytest tests/test_risk_engine.py -v` exits 0
7. Total tests so far: 16+

### Tests required (4)
1. Empty findings → score 0, classification "LOW"
2. All-HIGH findings in critical category → classification "HIGH"
3. Mixed severities normalize correctly within 0–100
4. Breakdown by phase sums to total raw score

### Done definition
PR opened. SCRATCHPAD updated with: score and classification on DIVA test APK, any thresholds that produced unexpected results.

---

## Phase 6 — PDF Reports + Forensic Hashing (proposal Phase 6 + Feature 1)

### Goal
Generate downloadable PDF security report with forensic chain-of-custody metadata embedded. This is where the first MobSF-differentiator ships.

### Branch
`phase-6-reports-forensic`

### Files created
- `modules/report_generator.py`
- `tests/test_report_generator.py` — 3 tests
- `tests/test_forensic.py` — 3 tests

### Files modified
- `modules/forensic.py` — expand with chain-of-custody PDF integration helpers
- `modules/analyzer.py` — Phase 6 is the final phase; generates PDF after risk engine
- `templates/result.html` — wire up "Download PDF Report" button to `/analysis/<id>/report.pdf`

### In scope
- ReportLab-based PDF generation
- PDF structure per ARCHITECTURE.md §11.1:
  - **Cover page**: tool logo placeholder, title, app name, package name, **APK SHA-256 hash**, started/completed timestamps, analyst name field (default "Anonymous Analyst" — editable in future), tool version
  - **Risk summary**: classification, score, score breakdown bar chart, top issues
  - **Manifest findings section**: metadata, insecure flags, permissions, exported components, findings
  - **Source code findings section**: grouped by category, with file/line info
  - **Dynamic findings section** (only if dynamic was enabled): runtime events, findings
  - **OWASP MTW10 + CWE summary table**
  - **Audit log appendix**: chronological list from `audit_log` table
- PDF saved to `reports/<analysis_id>.pdf`
- `pdf_path` saved to `analyses` row
- `/analysis/<id>/report.pdf` route serves the file with correct MIME type
- Forensic guarantees: PDF includes hash that matches the uploaded APK, timestamps in ISO format, immutable audit log

### Out of scope
- SBP compliance section in PDF (Phase 7 adds this)
- Educational mode expansions in PDF (Phase 8 adds this)
- PDF templating engines (use ReportLab Platypus directly)
- HTML/Word export

### Task checklist
- [ ] `forensic.compute_sha256` already exists from Phase 1 — verify it's used correctly during upload
- [ ] `forensic.generate_audit_summary(analysis_id)` returns ordered list of audit entries for PDF inclusion
- [ ] `report_generator.generate(analysis_id) -> str` returns the PDF path
- [ ] PDF cover page includes hash, timestamps, tool version, analyst name field
- [ ] Risk summary page renders with score bar chart
- [ ] Findings sections grouped logically
- [ ] Audit log appendix is chronological
- [ ] Download button on result page works
- [ ] PDF is reproducible — same analysis → same content (modulo timestamps)
- [ ] All 6 tests pass (3 report + 3 forensic)

### Acceptance criteria
1. After analysis completes, "Download PDF Report" button is enabled
2. Downloaded PDF opens correctly in any PDF reader
3. Cover page shows correct APK hash (matches what's on result page)
4. Audit log appendix lists every phase start/complete event
5. PDF for the same analysis is byte-identical across two generations (except embedded timestamps)
6. Re-hashing the uploaded APK manually with `sha256sum` produces the same value as the PDF cover
7. `pytest tests/test_report_generator.py tests/test_forensic.py -v` exits 0
8. Total tests so far: 22+

### Tests required (6)
**Report (3):**
1. PDF is generated with non-zero size
2. Cover page contains the APK hash string
3. Findings section count matches DB findings count

**Forensic (3):**
1. `compute_sha256` matches `sha256sum` output for the same file
2. `audit` writes a row to `audit_log` table
3. Audit entries are ordered chronologically

### Done definition
PR opened. SCRATCHPAD updated with: page count of PDF on test APK, any layout issues to revisit in Phase 9 polish.

---

## Phase 7 — SBP Banking Compliance (Feature 2)

### Goal
Add Pakistan State Bank cybersecurity framework compliance checks. The second MobSF-differentiator.

### Branch
`phase-7-sbp-compliance`

### Files created
- `modules/sbp_compliance.py`
- `modules/patterns/sbp_rules.py` — SBP rule pack
- `tests/test_sbp_compliance.py` — 3 tests

### Files modified
- `modules/analyzer.py` — Phase 7 runs after detection phases but before risk engine (so its findings feed risk scoring)
- `modules/report_generator.py` — add SBP section to PDF (only if SBP was enabled)
- `templates/result.html` — add conditional SBP Compliance tab
- `templates/_partials/sbp_card.html` (new) — per-rule status card

### In scope
- Banking app heuristic per ARCHITECTURE.md §11.2:
  - Package name contains: `bank`, `pay`, `wallet`, `finance`, `cash`
  - App name contains: `bank`, `pay`, `wallet`, `JazzCash`, `EasyPaisa`, `HBL`, `MCB`, `UBL`, `Allied`, `Faysal`, `BankIslami`, `Meezan`
  - Permissions combo: `READ_SMS` + `READ_CONTACTS` + `INTERNET`
- If toggled on by user, run regardless of heuristic
- SBP rule pack with rules covering: TLS enforcement, sensitive data logging, root detection, screen capture protection, certificate pinning, OTP handling, biometric authentication, session timeout, secure storage of credentials, network security config
- Each rule reads from already-computed `manifest` and `source` results — SBP does NOT re-parse the APK
- Result page SBP Compliance tab (conditional render) shows compliance summary + per-rule status
- PDF includes SBP section when applicable

### Out of scope
- Other regional compliance frameworks (PSX, GDPR, HIPAA, PCI-DSS) — explicit non-goal
- Live SBP rule updates from a remote source — rules are static in code
- Banking-specific dynamic analysis (would require Phase 4 instrumentation)

### Task checklist
- [ ] `sbp_compliance.analyze(apk_path, manifest, source)` returns SBP findings
- [ ] Banking app heuristic correctly identifies test cases (use real Pakistani banking apps if available, or synthetic test APKs)
- [ ] At least 10 SBP rules defined in `patterns/sbp_rules.py`
- [ ] Each rule produces `compliance_status`: COMPLIANT / NON_COMPLIANT / NOT_APPLICABLE
- [ ] SBP findings written to `sbp_findings` table
- [ ] Result page SBP tab renders only when `sbp_enabled=True`
- [ ] PDF SBP section appears only when SBP was run
- [ ] All 3 tests pass

### Acceptance criteria
1. Upload a Pakistani banking APK with SBP enabled → see compliance summary on dedicated tab
2. Upload non-banking APK with SBP disabled → no SBP tab visible
3. Each SBP rule shows status and evidence (what triggered the determination)
4. PDF for SBP-enabled analysis includes SBP section
5. PDF for SBP-disabled analysis does NOT include SBP section
6. `pytest tests/test_sbp_compliance.py -v` exits 0
7. Total tests so far: 25+

### Tests required (3)
1. Banking app heuristic correctly identifies an APK with `JazzCash` in name
2. SBP rule for TLS enforcement correctly flags an APK with cleartext traffic
3. SBP findings excluded from result/PDF when `sbp_enabled=False`

### Done definition
PR opened. SCRATCHPAD updated with: total SBP rule count, compliance summary on test banking APK.

---

## Phase 8 — Educational Mode (Feature 3)

### Goal
Add per-finding expandable "Show Educational Detail" UI showing vulnerable snippet, fixed snippet, and plain-English "why this matters." The third MobSF-differentiator.

### Branch
`phase-8-educational-mode`

### Files created
- `modules/educational.py`
- `tests/test_educational.py` — 2 tests (one of them: "every pattern has remediation")

### Files modified
- `app.py` — add `GET /api/finding/<finding_id>/educational` route
- `templates/_partials/finding_card.html` — add expand/collapse button when `educational_enabled=True`
- `static/js/result.js` — implement expand button + XHR fetch + render educational content
- `static/css/result.css` — styling for vulnerable (red) / fixed (green) / explanation sections
- `modules/report_generator.py` — when `educational_enabled=True`, include the remediation snippets in the PDF body under each finding

### In scope
- `educational.get_remediation_for_finding(finding_id)` reads the finding's `pattern_id` from DB, looks up the matching pattern in `patterns/vuln_patterns.py`, returns its `remediation` dict
- Expand button only renders when the parent analysis has `educational_enabled=True`
- XHR call returns JSON; client renders three sections (vulnerable / fixed / why)
- Syntax highlighting: keep it simple — monospace font + a subtle background tint per section. No Prism.js, no Highlight.js (extra dep, not worth it for a single language)
- PDF body expanded with remediation content when educational mode is on

### Out of scope
- Editable remediation content — patterns are static
- User-contributed explanations or comments
- Educational content for manifest, dynamic, or SBP findings (only source code patterns have remediation dicts per ARCHITECTURE.md §11.3)
- Interactive code editors (Monaco, CodeMirror)

### Task checklist
- [ ] Audit `patterns/vuln_patterns.py`: **every pattern has a complete `remediation` dict**. Test enforces this.
- [ ] `educational.get_remediation_for_finding(finding_id)` returns the right dict
- [ ] `/api/finding/<finding_id>/educational` returns JSON `{vulnerable_snippet, fixed_snippet, explanation}` or 404
- [ ] Finding cards render expand button when `educational_enabled=True`
- [ ] XHR call on click fetches and renders content; second click collapses
- [ ] CSS distinguishes vulnerable (red tint) / fixed (green tint) / explanation (neutral)
- [ ] PDF includes remediation content for source findings when educational is on
- [ ] Both tests pass

### Acceptance criteria
1. Upload DIVA with Educational Mode enabled → source code findings show "▾ Show Educational Detail" button
2. Click expands inline with three subsections
3. Click again collapses
4. Vulnerable code shown in red-tinted background
5. Fixed code in green-tinted background
6. Without Educational Mode: no buttons appear, normal finding cards
7. PDF for educational-enabled analysis includes the snippets in finding details
8. `pytest tests/test_educational.py -v` exits 0
9. Total tests so far: 27+

### Tests required (2)
1. Every pattern in `VULN_PATTERNS` has a complete `remediation` dict (this is the integrity test)
2. `get_remediation_for_finding` returns correct dict for a known finding

### Done definition
PR opened. SCRATCHPAD updated with: total patterns covered by remediation content, any UI rendering quirks.

---

## Phase 9 — Testing & Polish

### Goal
Backfill tests to hit 34+, add performance benchmark, end-to-end smoke test, polish empty/error/loading states, finalize README.

### Branch
`phase-9-testing-polish`

### Files created
- `tests/test_orchestrator.py` — 2 end-to-end tests with mocked phases
- `tests/test_performance.py` — 1 benchmark test
- `tests/fixtures/sample_apks/README.md` — instructions for downloading test APKs (we don't commit binaries)

### Files modified
- `README.md` — finalize with full setup, usage, troubleshooting, viva-prep walkthrough
- `templates/index.html` — polish: better empty state, drag-drop animation
- `templates/result.html` — polish: loading state, error state when status='failed'
- `templates/dashboard.html` — empty state ("No analyses yet")
- `static/css/main.css` — minor polish, hover states, focus rings for accessibility
- Any module flagged for revisit in earlier SCRATCHPAD entries

### In scope
- Reach **34+ total tests** per chapter claim
- Performance benchmark: a small APK (≤5MB) completes Phases 2+3 in under 60 seconds — test asserts this
- End-to-end orchestrator test with all phases mocked
- README sections: setup, usage, troubleshooting, architecture overview, how to add new patterns, FAQ
- Manual viva walkthrough checklist appended to README

### Out of scope
- New features
- New analyzer modules
- Database schema changes
- Anything that should have been done in Phases 1–8 (those should already be locked)

### Task checklist
- [ ] Count current tests — backfill until total ≥ 34
- [ ] `test_orchestrator.py` covers happy path + failure path
- [ ] `test_performance.py` benchmark passes (or fails loudly with clear timing info)
- [ ] README has: Quick Start, Detailed Setup, Usage Walkthrough, Architecture Overview, Adding Patterns, Troubleshooting, References
- [ ] README includes a viva-prep checklist Nayab can run through
- [ ] All polish items addressed (empty states, error states, loading states)
- [ ] End-to-end manual smoke test: upload DIVA → all phases complete → PDF downloads cleanly → dashboard updates
- [ ] `pytest --cov=modules` runs clean with coverage report

### Acceptance criteria
1. `pytest -v` shows **34 or more tests passing**
2. Performance benchmark passes
3. End-to-end manual test on DIVA APK completes within 3 minutes
4. README is sufficient that a new user can clone, install, and run without external guidance
5. All UI states (empty, loading, error, success) are styled and consistent
6. No console errors in browser
7. No Python deprecation warnings during `pytest`

### Done definition
PR opened. SCRATCHPAD updated with: final test count, coverage percentage, performance benchmark numbers. After this PR merges, the project is feature-complete and demo-ready.

---

## Phase 10 — UI Redesign (post-v1.0.0)

### Goal
Replace the functional UI built across Phases 1–9 with the approved visual design: a hero section, a 5-step pipeline strip, an upload card, a 4-card feature grid, and a polished dashboard table with colored action buttons. **Frontend only — zero changes to analysis logic, database, routes, or any module under `modules/`.**

### Branch
`phase-10-ui-redesign` (branch from `main` if Phase 9 is merged; otherwise from `phase-9-testing-polish`)

### Files modified
- `templates/base.html` — new header (logo + Analyze/Dashboard nav) and two-line brand footer
- `templates/index.html` — hero section, pipeline strip, upload card, 4 feature cards
- `templates/dashboard.html` — title row with "+ New Analysis" button, polished table with colored View/PDF/Del buttons
- `templates/result.html` — adopt the new header/footer/fonts (tab structure and content unchanged)
- `templates/_partials/finding_card.html` — restyle to match (no behavior change)
- `static/css/main.css` — full visual system per CLAUDE.md §5 (palette, monospace accents, gradient title, card styling, button colors)
- `static/css/dashboard.css`, `static/css/result.css` — restyle to match
- `static/js/main.js` — drag-drop + the three toggles wired to the new markup; "Start Analysis" disabled until a file is selected
- `config.py` — `MAX_UPLOAD_SIZE_MB` → 100; add a footer-year value (or render `datetime.now().year` in the template)

### In scope
- Implement the home page exactly per the approved mockup and ARCHITECTURE.md §5: hero (monospace badge → gradient two-line title → description), pipeline strip (5 step cards with arrows), upload card (drag-drop + three toggles + Start Analysis), 4 feature cards
- Implement the dashboard exactly per the approved mockup: "Analysis Dashboard" title + "+ New Analysis" button, table with ID (monospace cyan link), APK File, Risk Level (pill), Score, Vulnerabilities, Date, Actions (View/PDF/Del colored buttons)
- Apply the new header + footer + fonts + accent treatment to the result page without changing its tab structure or content
- Color palette, typography, and components per CLAUDE.md §5

### Out of scope (HARD)
- **Any change to `modules/` (analysis logic, risk engine, report generator, etc.)** — this is presentation only
- **Any database schema change**
- **Any route signature change** — the same routes render the same data, just restyled
- **Removing or hiding the SBP and Educational toggles** — all three toggles stay (see the warning below)
- New analysis features, new patterns, new detection logic

### CRITICAL — keep all three toggles
The approved mockup shows only the "Enable Dynamic Analysis" toggle. This is a mockup omission, NOT an instruction to remove features. The options panel MUST retain all three toggles — Dynamic, SBP Banking Compliance, Educational Mode — styled identically. SBP (Phase 7) and Educational (Phase 8) are core differentiators; removing them from the UI would orphan two phases of working code and gut the project's value proposition.

### Task checklist
- [ ] Header: "SecureAPK" logo left, "Analyze" / "Dashboard" nav right, active state on current page
- [ ] Hero: monospace cyan-bordered badge, two-line title with cyan→blue gradient on line 2, muted description
- [ ] Pipeline strip: 5 step cards (APK Upload → Manifest Analysis → Code Scanning → Runtime Monitor → Risk Report) joined by arrows, monospace labels
- [ ] Upload card: dashed drag-drop zone, "max 100 MB" text, selected-file preview, three toggles, full-width blue "Start Analysis →" button disabled until a file is chosen
- [ ] Feature cards: 4-column grid (Manifest Inspection, Source Code Scanning, Runtime Monitoring, Risk Scoring) with icon + title + description
- [ ] Dashboard: title row + "+ New Analysis" button; table columns ID/APK File/Risk Level/Score/Vulnerabilities/Date/Actions; ID monospace cyan; Risk Level pill; View=blue, PDF=green, Del=red; row hover
- [ ] Result page: new header + footer + fonts applied; tabs and content unchanged
- [ ] All colors/fonts pulled from CLAUDE.md §5 (no ad-hoc values)
- [ ] Two-line brand footer with year from config/template (not hardcoded)
- [ ] `MAX_UPLOAD_SIZE_MB` set to 100; UI text agrees
- [ ] Full test suite still green (this is a frontend change; all 42 tests must still pass — if any break, the change touched logic it shouldn't have)
- [ ] Manual smoke test: upload an APK with all three toggles on → all phases run → result page renders with new chrome → PDF still downloads → dashboard shows the new table

### Acceptance criteria
1. Home page matches the approved mockup: hero, pipeline strip, upload card, 4 feature cards
2. All three toggles (Dynamic, SBP, Educational) present and functional in the options panel
3. Dashboard matches the approved mockup: title row + New Analysis button + polished table with colored action buttons
4. Result page adopts the new header/footer/fonts; all six tabs still render correctly
5. `pytest tests/ -v` still shows **42+ tests passing** (no logic touched, so no test should break)
6. End-to-end manual flow works: upload → analyze → view tabs → download PDF → dashboard
7. No console errors in the browser; upload size text reads "max 100 MB"

### Tests required
None new. This is a presentation-only change. The existing 42-test suite is the regression guard — if a test breaks, the change reached into logic it should not have, and that must be reverted. Confirm the full suite is green in the PR description.

### Done definition
PR opened from `phase-10-ui-redesign` titled `Phase 10: UI Redesign` as draft. PR description confirms: all three toggles retained, 42 tests still green, screenshots of the new home + dashboard + result pages. SCRATCHPAD updated with the Phase 10 entry.

---

## Phase 11 — Court-Admissible Forensic Report

### Goal
Expand the PDF report produced by Phase 6 so it is court-admissible under **ISO/IEC 27037:2012** (Guidelines for identification, collection, acquisition and preservation of digital evidence). Adds a proper forensic cover, software environment block, methodology statement, chain-of-custody appendix, verification instructions, timezone-aware timestamps, and page numbers. Preserves the existing report layout from Phase 6 — adds to it, does not redesign it.

### Branch
`phase-11-court-admissible-report`

If Phase 10 has shipped: branch from `phase-10-ui-redesign` (or `main` if merged). If Phase 10 hasn't run yet: branch from `phase-9-testing-polish` (or `main` if Phase 9 is merged). The work is independent of the UI redesign; either order is workable.

### Files modified
- `modules/report_generator.py` — significant expansion: forensic cover, env block, methodology, chain-of-custody appendix, verification instructions, page-numbered footers, timezone-aware timestamps
- `modules/forensic.py` — new helpers: `compute_multi_hash()` (SHA-256/SHA-1/MD5), `get_software_environment()` (Python/Jadx/ADB/OS versions), `format_iso8601_with_tz()`, `format_chain_of_custody()`
- `modules/db_manager.py` — `ALTER TABLE analyses ADD COLUMN analyst_name TEXT` migration in the schema-init code (idempotent — safe to re-run); add `set_analyst_name()` helper
- `modules/analyzer.py` — accept `analyst_name` in options, persist to the analyses row, include in audit log entries
- `app.py` — handle the new `analyst_name` form field on `POST /upload`
- `templates/index.html` — add an optional **"Analyst Name"** text input next to the three toggles on the upload card. Placeholder text: `Optional — defaults to "Anonymous Analyst"`. Maximum 100 characters.
- `templates/result.html` — display the analyst name in the result page metadata block when set
- `config.py` — add `REPORT_TIMEZONE` setting (default value derived from system local time; documented but configurable for analysts in different jurisdictions)

### Files created
- `tests/test_court_admissible_report.py` — 4 tests covering: presence of SHA-256 on cover, presence of chain-of-custody appendix, ISO 8601 timestamp format, page-number footer format

### In scope (per ARCHITECTURE.md §11.1)

**New cover-page structure (5 blocks in order):**
1. **Tool identification** — `SecureAPK v1.0.0`, one-line description, report-generation timestamp in ISO 8601 with timezone
2. **Case identification** — analysis ID as case number, analyst name (from form field or default), institution
3. **Evidence identification** — APK filename, size in bytes, **SHA-256** (prominent, monospace), SHA-1, MD5, package name, version, version code
4. **Software environment** — host OS+version, Python version, Jadx version, ADB version, SecureAPK version
5. **Statement of Methodology** — short paragraph citing ISO/IEC 27037:2012 and describing the six-phase methodology

**Body changes:**
- Each phase heading carries the UTC completion timestamp inline: e.g., `Phase 2: Manifest Analysis Findings (completed 2026-05-31T14:41:48+05:00)`
- All other body content from Phase 6 stays as-is

**New appendices (at the end of the report, in order):**
1. **Chain of Custody** — chronological dump of every `audit_log` entry for this analysis. Columns: timestamp (ISO 8601 with TZ), actor, action, details
2. **Verification of Evidence Integrity** — explicit step-by-step instructions: locate the original APK, run `sha256sum` (or equivalent), compare to the value on the cover, conclude

**Document-level changes:**
- Page numbers `Page X of Y` in every footer
- Generation stamp in every footer: `Generated by SecureAPK v1.0.0 — <ISO timestamp>`
- All timestamps formatted ISO 8601 with explicit TZ offset

### Out of scope (HARD)
- **No digital signatures** (no PKI; out of FYP scope) — integrity rests on visible SHA-256 + byte-identical regeneration + chain-of-custody
- **No layout redesign** — keep the Phase 6 visual style; this phase ADDS content, doesn't restructure existing sections
- **No changes to analysis logic** (`manifest_analyzer`, `source_analyzer`, `dynamic_analyzer`, `sbp_compliance`, `educational`, `risk_engine`)
- **No notarisation or external timestamp authority**
- **No new analysis features**

### Critical reminders

- **`pageCompression=0` and byte-identical regeneration (Phase 6 D-14, D-15) must be preserved.** The expanded report must still regenerate byte-identically (except embedded timestamps).
- **All hashes computed from the same source bytes** the APK file occupies on disk. Use the file path saved on the `analyses` row, not a re-uploaded copy.
- **Analyst name max length 100 chars, sanitised** — strip control chars before display, HTML-escape in the result page, escape special chars before embedding in the PDF.
- **DB migration must be idempotent** — running `setup.py` on a fresh DB OR on a DB that already has `analyst_name` must both succeed. Pattern: `PRAGMA table_info(analyses)` → check if column exists → ALTER if missing.
- **Backwards compatibility** — old analyses (created before Phase 11) have NULL `analyst_name`. Render them as "Anonymous Analyst" on both result page and PDF. The chain-of-custody appendix works for old analyses too (audit_log entries exist regardless).
- **All 42+ tests must still pass.** Phase 11 adds 4 new tests for a target of 46+.
- **All DB writes via `db_manager`** (including the new `set_analyst_name`).

### Task checklist
- [ ] DB migration: `analyst_name TEXT` column on `analyses` (idempotent ALTER)
- [ ] Upload form field: optional `analyst_name` text input, max 100 chars, placeholder text
- [ ] Persist `analyst_name` from POST /upload through to the analyses row
- [ ] `forensic.compute_multi_hash(apk_path)` returns `{sha256, sha1, md5}`
- [ ] `forensic.get_software_environment()` returns `{os, python, jadx, adb, secureapk}` (each a string version or "not installed")
- [ ] `forensic.format_iso8601_with_tz(dt)` returns timestamp like `2026-05-31T14:41:50+05:00 (PKT)`
- [ ] `forensic.format_chain_of_custody(analysis_id)` returns audit_log rows ready for PDF rendering
- [ ] Cover page: 5 blocks in order (Tool / Case / Evidence / Environment / Methodology)
- [ ] Body: phase headings carry completion timestamps
- [ ] Appendices: Chain of Custody + Verification of Evidence Integrity (in that order)
- [ ] Footer on every page: `Page X of Y` and the generation stamp
- [ ] Methodology statement explicitly references ISO/IEC 27037:2012
- [ ] Regenerate twice — confirm byte-identical except for the runtime generation timestamp
- [ ] Run `pytest tests/ -v` — 46+ tests pass
- [ ] Manual smoke test: upload an APK with the Analyst Name field filled, confirm the name appears in the result page and on the PDF cover; upload without filling it, confirm "Anonymous Analyst" is used; verify `sha256sum` of the uploaded APK matches the cover hash

### Acceptance criteria
1. PDF cover has all 5 forensic blocks (Tool / Case / Evidence / Environment / Methodology)
2. SHA-256, SHA-1, MD5 all visible in the Evidence Identification block, monospace
3. Methodology section explicitly cites **ISO/IEC 27037:2012**
4. Every page footer shows `Page X of Y` and the generation stamp
5. All timestamps in the report use ISO 8601 with explicit timezone offset (`+HH:MM` format)
6. Chain of Custody appendix lists every audit_log row chronologically with actor, action, and details
7. Verification of Evidence Integrity appendix gives step-by-step instructions for hash verification
8. Re-running `sha256sum` on the original APK file produces a hash that matches the cover
9. Analyst Name field appears on the upload form, accepts up to 100 chars, persists, and renders in both the result page and the PDF
10. Two consecutive regenerations of the same analysis produce byte-identical PDFs (except for the in-footer generation timestamp)
11. `pytest tests/ -v` shows **46 or more** tests passing
12. Old analyses (NULL `analyst_name`) render correctly as "Anonymous Analyst"

### Tests required (exactly 4)
1. **SHA-256 visible on cover** — generate the PDF for a known analysis, extract text bytes, assert the SHA-256 string appears in the cover area (first ~30% of bytes)
2. **Chain-of-custody appendix present** — assert the PDF contains the text "Chain of Custody" AND that the number of audit-log entries in the body matches the DB count for that analysis
3. **ISO 8601 timestamp format with timezone** — assert every timestamp in the report body matches the regex `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2}`
4. **Page-number footer format** — assert every page contains the literal `Page X of Y` pattern (using a PDF text-extraction library or by checking the source bytes since `pageCompression=0` keeps them readable)

### Done definition
PR opened from `phase-11-court-admissible-report` titled `Phase 11: Court-Admissible Forensic Report` as draft. PR description: each acceptance criterion ticked, sample regenerated PDF size + byte-identical confirmation, total test count (46+). SCRATCHPAD updated with Phase 11 entry.

---

## After Phase 11

Once Phase 11 ships:
1. The PDF report is forensically defensible: shows the SHA-256, cites ISO/IEC 27037, includes chain-of-custody and verification instructions
2. **Re-tag a release** to reflect the forensic-grade report (e.g., `v1.2.0`)
3. **Update the SOP screenshots** for the report section to match the new format
4. **Update Chapter 6 of the FYP documentation** when written to reflect the expanded report contract

Once Phase 10 ships:
1. **Re-tag a release**: `v1.1.0` (UI overhaul on top of the v1.0.0 feature-complete base)
2. **Refresh the SOP screenshots** — the Standard Operating Procedure document's screenshot placeholders should be filled using the redesigned UI
3. **Rehearse viva walkthrough** using the README's checklist against the new UI
4. **Come back to this chat** for Chapters 4–7 of the FYP documentation (still unblocked — code-doc alignment remains automatic; only the UI screenshots in Chapter 6 change)

---

*This file is the execution roadmap. Any phase reordering, addition, or scope change requires explicit approval in the planning chat. Last updated: Phase 10 (UI Redesign) added.*
