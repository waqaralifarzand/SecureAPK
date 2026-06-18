# Source Material for Chapter 6 (Implementation and Testing) and Chapter 7 (Results and Discussion)

**Extraction basis:** repo `waqaralifarzand/secureapk`, branch `claude/charming-keller-izsv8o`, commit `85ce1c9` (2026-06-16 20:56:17 +0500).
**Method:** read-only inspection of the working tree as checked out; no files were modified. Every code block below is a verbatim, unedited excerpt with its exact file path and line range. Per-test descriptions and the Part C pass count come from actually executing the suite (`.venv/bin/python -m pytest`), not static guessing.
**Note on staleness:** the task brief states this checkout may lag behind your newer local working copy. Part E lists every place this snapshot diverges from what the brief assumed exists. Treat Part E as the authoritative diff list — if you've since added the missing pieces locally, the corresponding chapter text should cite your local files, not this document.

This file is extraction-only: file path + line range + literal code + one caption sentence. No surrounding narrative prose is supplied — that is left for you to write in the chapter body.

---

## PART A — Chapter 6.1 Code Listings

### A.1 — `modules/analyzer.py` — orchestrator: option toggles and phase dispatch

**File:** `modules/analyzer.py`, lines 20–28 (`AnalysisOptions` dataclass)

```python
@dataclass
class AnalysisOptions:
    dynamic_enabled: bool = False
    sbp_enabled: bool = False
    educational_enabled: bool = False

    def to_dict(self) -> dict:
        return asdict(self)
```

*Significance: this dataclass is the entire surface of user-controlled analysis options — there are exactly three boolean toggles, each gating one optional phase or one report feature.*

**File:** `modules/analyzer.py`, lines 30–165 (`run_analysis`, full function)

```python
def run_analysis(analysis_id: str, apk_path: str, options: AnalysisOptions) -> None:
    """Phase 1 placeholder. Logs the phase sequence and marks status='completed'.

    The real per-phase implementations are added in Phases 2-6.
    """
    try:
        forensic.audit("analysis_started", analysis_id, details=options.to_dict())

        analysis = db_manager.get_analysis(analysis_id)
        if analysis:
            forensic.audit(
                "hash_verified",
                analysis_id,
                details={"sha256": analysis["apk_hash_sha256"]},
            )

        # Phase 2 — Manifest static analysis.
        db_manager.set_current_phase(analysis_id, 2)
        manifest = manifest_analyzer.analyze(apk_path)
        db_manager.save_manifest_metadata(analysis_id, manifest)
        db_manager.save_permissions(analysis_id, manifest["permissions"])
        db_manager.save_exported_components(analysis_id, manifest["exported_components"])
        db_manager.save_findings(analysis_id, manifest["findings"])
        db_manager.set_parser_used(analysis_id, manifest["parser_used"])
        forensic.audit(
            "phase_2_completed",
            analysis_id,
            details={
                "findings": len(manifest["findings"]),
                "parser_used": manifest["parser_used"],
                "dangerous_permissions": sum(1 for p in manifest["permissions"] if p["is_dangerous"]),
            },
        )
        db_manager.set_progress(analysis_id, 25)

        # Phase 3 — Source code static analysis.
        db_manager.set_current_phase(analysis_id, 3)
        source = source_analyzer.analyze(apk_path)
        db_manager.save_findings(analysis_id, source["findings"])
        db_manager.add_audit_entry(
            analysis_id, "source_decompiler", details=source["decompiler_used"],
        )
        forensic.audit(
            "phase_3_completed",
            analysis_id,
            details={
                "findings": len(source["findings"]),
                "decompiler_used": source["decompiler_used"],
                "files_scanned": source["files_scanned"],
                "categories": source["categories_triggered"],
            },
        )
        db_manager.set_progress(analysis_id, 50)

        # Phase 4 — Dynamic runtime analysis (optional).
        dynamic = None
        if options.dynamic_enabled:
            db_manager.set_current_phase(analysis_id, 4)
            dynamic = dynamic_analyzer.analyze(apk_path, manifest.get("package_name"))
            db_manager.save_runtime_events(analysis_id, dynamic["events"])
            db_manager.save_findings(analysis_id, dynamic["findings"])
            db_manager.add_audit_entry(
                analysis_id, "dynamic_status", details=dynamic["status"],
            )
            forensic.audit(
                "phase_4_completed",
                analysis_id,
                details={
                    "status": dynamic["status"],
                    "events": len(dynamic["events"]),
                    "findings": len(dynamic["findings"]),
                    "logcat_seconds": dynamic["logcat_duration_seconds"],
                },
            )
        db_manager.set_progress(analysis_id, 70)

        # Phase 7 — SBP compliance (optional). Runs BEFORE the risk engine
        # so non-compliant rules feed the `sbp` bucket in
        # breakdown_by_phase. SBP does NOT re-parse the APK; it consumes
        # the manifest + source + dynamic dicts already in memory.
        if options.sbp_enabled:
            db_manager.set_current_phase(analysis_id, 7)
            sbp = sbp_compliance.analyze(apk_path, manifest, source, dynamic)
            db_manager.save_sbp_findings(analysis_id, sbp["rules"])
            db_manager.add_audit_entry(
                analysis_id, "sbp_status",
                details=f"banking={sbp['is_banking_app']}, "
                        f"non_compliant={sbp['non_compliant_count']}",
            )
            forensic.audit(
                "phase_7_completed", analysis_id,
                details={
                    "is_banking_app": sbp["is_banking_app"],
                    "counts": sbp["counts"],
                },
            )
        db_manager.set_progress(analysis_id, 80)

        # Phase 5 — Risk scoring + OWASP/CWE aggregation.
        db_manager.set_current_phase(analysis_id, 5)
        risk = risk_engine.compute(analysis_id)
        db_manager.save_risk(analysis_id, risk)
        forensic.audit(
            "phase_5_completed",
            analysis_id,
            details={
                "score": risk["normalized_score"],
                "classification": risk["classification"],
                "owasp": risk["owasp_categories_triggered"],
            },
        )
        db_manager.set_progress(analysis_id, 90)

        # Mark completion BEFORE Phase 6 so the PDF embeds the final
        # completed_at timestamp on its cover. The audit entry for
        # "analysis_completed" is still appended after report generation.
        db_manager.mark_completed(analysis_id)

        # Phase 6 — Forensic-grade PDF report.
        db_manager.set_current_phase(analysis_id, 6)
        try:
            pdf_path = report_generator.generate(analysis_id)
            db_manager.set_pdf_path(analysis_id, pdf_path)
            forensic.audit("phase_6_completed", analysis_id,
                            details={"pdf": pdf_path})
        except Exception as e:  # noqa: BLE001 - PDF failure must not nuke the analysis
            log.exception("PDF generation failed for analysis %s", analysis_id)
            forensic.audit("phase_6_failed", analysis_id, details={"error": str(e)})

        forensic.audit("analysis_completed", analysis_id)

    except Exception as e:  # never silently swallow
        log.exception("analysis %s failed", analysis_id)
        db_manager.mark_failed(analysis_id, str(e))
        forensic.audit("analysis_failed", analysis_id, details={"error": str(e)})
        raise
```

*Significance: this single function is the entire phase-sequencing contract of the tool — it is the only place that decides phase order, which phases are conditional, and how failure is surfaced, with Phase 4 and Phase 7 wrapped in `if options.dynamic_enabled` / `if options.sbp_enabled` guards and Phase 6 wrapped in its own try/except so a PDF failure cannot fail an otherwise-successful analysis.*

> **Discrepancy flag (see Part E for detail):** the task brief described toggles for "dynamic/SBP/educational/deep bytecode." Only three toggles exist in this checkout — `dynamic_enabled`, `sbp_enabled`, `educational_enabled` — confirmed against the dataclass above, the three `<input type="checkbox">` elements in `templates/index.html` (lines 73, 83, 92), and the three keyword arguments built from `request.form` in `app.py` lines 57–60. There is no fourth "deep bytecode" toggle anywhere in this repo. Additionally, note that `educational_enabled` is read and serialized into the audit log (line 36, via `options.to_dict()`) but, unlike `dynamic_enabled`/`sbp_enabled`, it does **not** gate a phase inside `run_analysis` — there is no `if options.educational_enabled:` branch in this function. It is consumed later, only inside `report_generator.py` (`analysis.get("educational_enabled")`, used at line 151 of that file) to decide whether to append remediation blocks to the PDF.

---

### A.2 — `modules/manifest_analyzer.py` — three-tier fallback chain

**File:** `modules/manifest_analyzer.py`, lines 37–55

```python
def analyze(apk_path: str) -> dict[str, Any]:
    """Run the manifest analysis pipeline with fallbacks. Never raises."""
    try:
        result = _analyze_with_pyaxmlparser(apk_path)
        result["parser_used"] = "pyaxmlparser"
        return _finalize(result)
    except Exception as e:  # noqa: BLE001 — fallback path is by design
        log.warning("PyAXMLParser failed for %s: %s", apk_path, e)

    try:
        result = _analyze_with_aapt(apk_path)
        result["parser_used"] = "aapt"
        return _finalize(result)
    except Exception as e:  # noqa: BLE001
        log.warning("aapt fallback failed for %s: %s", apk_path, e)

    result = _analyze_with_dex_strings(apk_path)
    result["parser_used"] = "dex_strings"
    return _finalize(result)
```

*Significance: this is the literal three-tier fallback — PyAXMLParser primary, `aapt dump badging` as fallback 1, raw ZIP/DEX string extraction as fallback 2 — and the third tier is unconditional (no try/except) precisely because it is documented to never raise, guaranteeing `analyze()` always returns a result dict.*

Supporting tier implementations in the same file, for chapter cross-reference: `_analyze_with_pyaxmlparser` (lines 62–117), `_analyze_with_aapt` (lines 174–219), `_analyze_with_dex_strings` (lines 236–285), `_finalize` (lines 322–406, builds `Finding` rows for dangerous permissions / debuggable / cleartext / backup / missing network-security-config / exported components), `_finding` factory (lines 409–424).

---

### A.3 — `modules/source_analyzer.py` — Jadx invocation and regex pattern loop

**File:** `modules/source_analyzer.py`, lines 57–80 (`_analyze_with_jadx`)

```python
def _analyze_with_jadx(apk_path: str) -> dict[str, Any]:
    jadx = config.JADX_PATH or "jadx"
    with tempfile.TemporaryDirectory(prefix="secureapk_jadx_") as tmp:
        out_dir = Path(tmp)
        proc = subprocess.run(
            [jadx, "--no-res", "--output-dir", str(out_dir), apk_path],
            capture_output=True, text=True,
            timeout=config.JADX_TIMEOUT_SECONDS,
        )
        # Jadx exits non-zero on partial decompilation but still produces output.
        # We trust the disk artefacts over the exit code.
        if not any(out_dir.rglob("*.java")):
            raise RuntimeError(f"Jadx produced no .java output (rc={proc.returncode})")

        findings, files_scanned = _scan_java_tree(out_dir)

    categories = sorted({f["category"] for f in findings})
    return {
        "decompiled": True,
        "decompiler_used": "jadx",
        "files_scanned": files_scanned,
        "findings": findings,
        "categories_triggered": categories,
    }
```

*Significance: Jadx is run with `--no-res` into a `tempfile.TemporaryDirectory`, and success is judged by the presence of `.java` files on disk rather than Jadx's exit code — a deliberate choice because Jadx often exits non-zero on partial decompilation while still emitting usable source.*

**File:** `modules/source_analyzer.py`, lines 83–114 (`_scan_java_tree`)

```python
def _scan_java_tree(root: Path) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()   # (pattern_id, file_location) dedup
    files_scanned = 0

    compiled = [(p, re.compile(p["regex"])) for p in VULN_PATTERNS]

    for java in root.rglob("*.java"):
        files_scanned += 1
        try:
            text = java.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        rel = java.relative_to(root).as_posix()

        for pattern, rx in compiled:
            key = (pattern["id"], rel)
            if key in seen_keys:
                continue
            for lineno, line in enumerate(lines, start=1):
                if rx.search(line):
                    findings.append(_make_finding(
                        pattern=pattern,
                        file_location=rel,
                        line_number=lineno,
                        code_snippet=_snippet(lines, lineno),
                    ))
                    seen_keys.add(key)
                    break  # first match per (pattern_id, file) only

    return findings, files_scanned
```

*Significance: this is the regex-pattern loop over every decompiled `.java` file — patterns are precompiled once outside the file loop for performance, and the `seen_keys` set enforces first-match-only per `(pattern_id, file)` pair, which is the deduplication mechanism verified by `tests/test_source_analyzer.py::test_pattern_dedup_within_a_file`.*

---

### A.4 — `modules/dynamic_analyzer.py` — ADB pipeline

**File:** `modules/dynamic_analyzer.py`, lines 77–176 (`_run_pipeline`, full function)

```python
def _run_pipeline(apk_path: str, package_name: str) -> dict[str, Any]:
    adb = _adb()

    emulator = _detect_emulator(adb)
    if emulator is None:
        return _result(
            status="skipped_no_emulator",
            status_message=(
                "No Android emulator detected. To enable dynamic analysis: "
                "open Android Studio -> Device Manager -> start an AVD, then "
                "re-upload the APK with Dynamic Analysis enabled."
            ),
        )

    installed = False
    events: list[dict[str, Any]] = []
    status = "completed"
    status_message = "Dynamic analysis completed successfully."
    logcat_seconds = 0
    logcat_proc = None

    try:
        # 2. Install -----------------------------------------------------
        try:
            _run([adb, "-s", emulator, "install", "-r", "-t", apk_path],
                 timeout=120)
            installed = True
        except subprocess.TimeoutExpired:
            return _result(status="skipped_install_failed", emulator_id=emulator,
                           status_message=("adb install timed out after 120s. "
                                           "Emulator may be unresponsive."))
        except subprocess.CalledProcessError as e:
            return _result(status="skipped_install_failed", emulator_id=emulator,
                           status_message=f"adb install failed: {_clip(e.stderr)}")

        # 3. Clear logcat buffer and start capture BEFORE monkey ---------
        #    This ensures we capture events generated during app execution.
        try:
            _run([adb, "-s", emulator, "logcat", "-c"], timeout=10)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass  # non-fatal: we may capture stale entries, but won't miss new ones

        logcat_proc = _start_logcat(adb, emulator)
        logcat_start = time.monotonic()

        # 4. Launch via monkey ------------------------------------------
        try:
            _run([adb, "-s", emulator, "shell", "monkey", "-p", package_name,
                  "-c", "android.intent.category.LAUNCHER",
                  str(config.DYNAMIC_MONKEY_EVENT_COUNT)], timeout=60)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            log.warning("monkey launch failed for %s: %s", package_name, e)
            status = "partial"
            status_message = "App was installed but failed to launch via monkey."

        # 5. Settle time — let the app finish responding to events ------
        settle = config.DYNAMIC_LOGCAT_SETTLE_SECONDS
        time.sleep(settle)

        # 6. Terminate logcat and read output ---------------------------
        logs, logcat_seconds = _finish_logcat(logcat_proc, logcat_start)
        logcat_proc = None
        events = _classify_logcat(logs, package_name)

        # 7. Best-effort permission snapshot - failure is non-fatal.
        try:
            _run([adb, "-s", emulator, "shell", "dumpsys", "package",
                  package_name], timeout=15)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

    except Exception as e:  # noqa: BLE001 - this method MUST NOT raise
        log.exception("dynamic analyzer pipeline error")
        status = "partial"
        status_message = f"Dynamic analysis encountered an error: {e!s}"
    finally:
        # Kill logcat if still running (e.g. after an exception).
        if logcat_proc is not None:
            _terminate(logcat_proc)
            try:
                logcat_proc.communicate(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                logcat_proc.kill()
        # 7. Uninstall ALWAYS runs - even on partial failure.
        if installed:
            try:
                subprocess.run([adb, "-s", emulator, "uninstall", package_name],
                               capture_output=True, text=True, timeout=15)
            except (subprocess.TimeoutExpired, OSError) as e:
                log.warning("APK uninstall failed for %s: %s", package_name, e)

    findings = _events_to_findings(events)
    return _result(
        status=status,
        status_message=status_message,
        emulator_id=emulator,
        logcat_duration_seconds=logcat_seconds,
        events=events,
        findings=findings,
    )
```

*Significance: this single function carries out every documented ADB step in order — device detection, install with a hard timeout, logcat buffer clear, logcat capture started before the monkey launch (so launch-time events are not missed), monkey-driven launch, a configurable settle sleep, logcat termination/classification, a best-effort `dumpsys` permission snapshot, and an uninstall that runs unconditionally inside `finally` regardless of which step failed.*

---

### A.5 — `modules/androguard_analyzer.py` — bytecode checks via `androguard.misc.AnalyzeAPK`

**This file does not exist in this repository checkout.** Verified by five independent checks, each returning a negative/empty result:

1. **Directory listing** of `modules/` contains no `androguard_analyzer.py` (confirmed again via `find . -iname "*androguard*"` at the repo root, which returned zero hits for the project's own tracked code).
2. **Repo-wide case-insensitive grep** for the literal string `androguard` across `*.py`, `*.md`, `*.txt` returns exactly one hit outside of `.venv/` (a pip-installed, gitignored third-party dependency directory, not part of this repo): `CLAUDE (4).md` line 52 — `"Mature ecosystem for APK analysis (PyAXMLParser, Androguard family)."` — a parenthetical justification for choosing Python, not a reference to an implemented module.
3. **Targeted grep** for `androguard_analyzer|AndroguardAnalyzer|androguard\.misc|AnalyzeAPK` across the whole repo returns zero matches.
4. **`requirements.txt`** (6 lines: `flask`, `flask-wtf`, `pyaxmlparser`, `reportlab`, `pytest`, `pytest-cov`) does not list `androguard` as a dependency.
5. **`modules/analyzer.py`'s import block** (lines 11–14) imports exactly eight sibling modules — `db_manager, dynamic_analyzer, forensic, manifest_analyzer, report_generator, risk_engine, sbp_compliance, source_analyzer` — none of which is an androguard-based bytecode analyzer.

*Significance for Chapter 6: if your newer local working copy has since added this module, Chapter 6.1 should cite that local file directly; this snapshot cannot supply a code listing for something that is not present. See Part E for the consolidated gap entry.*

---

### A.6 — `modules/risk_engine.py` — scoring formula

**File:** `modules/risk_engine.py`, lines 64–110 (`compute_from_findings`, full function)

```python
def compute_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Same as compute() but takes findings directly. Used by tests."""
    raw_score = 0.0
    breakdown = {"manifest": 0.0, "source": 0.0, "dynamic": 0.0, "sbp": 0.0}
    scored: list[tuple[float, dict[str, Any]]] = []

    for f in findings:
        contrib = _score_contribution(f)
        raw_score += contrib
        bucket = _PHASE_BUCKET.get(f.get("phase"))
        if bucket:
            breakdown[bucket] += contrib
        scored.append((contrib, f))

    normalized = min(100, round(raw_score / config.SCORE_NORMALIZATION_DIVISOR * 100))
    classification = _classify(normalized)

    # Top 5 by individual contribution, descending.
    scored.sort(key=lambda pair: pair[0], reverse=True)
    top_issues = [f for _, f in scored[:5]]

    # OWASP / CWE aggregation. Prefer the value persisted on the finding row
    # but fall back to the category map for rows that didn't carry an explicit
    # owasp_id / cwe_id (e.g. Phase 4 dynamic findings).
    owasp_set: set[str] = set()
    cwe_set: set[str] = set()
    for f in findings:
        owasp = f.get("owasp_id") or CATEGORY_TO_OWASP.get(f.get("category", ""))
        cwe = f.get("cwe_id") or CATEGORY_TO_CWE.get(f.get("category", ""))
        if owasp:
            owasp_set.add(owasp)
        if cwe:
            cwe_set.add(cwe)

    return {
        "raw_score": round(raw_score, 2),
        "normalized_score": int(normalized),
        "classification": classification,
        "breakdown_by_phase": {k: round(v, 2) for k, v in breakdown.items()},
        "top_issues": top_issues,
        "owasp_categories_triggered": sorted(
            owasp_set, key=lambda m: int(m.lstrip("M")) if m.startswith("M") and m[1:].isdigit() else 99,
        ),
        "owasp_names": {m: OWASP_MTW10_2024[m] for m in owasp_set if m in OWASP_MTW10_2024},
        "cwes_triggered": sorted(cwe_set),
        "total_findings": len(findings),
    }
```

**File:** `modules/risk_engine.py`, lines 113–119 (`_score_contribution`)

```python
def _score_contribution(finding: dict[str, Any]) -> float:
    severity = (finding.get("severity") or "").upper()
    weight = config.SEVERITY_WEIGHTS.get(severity, 0)
    if weight == 0:
        return 0.0
    multiplier = config.CATEGORY_MULTIPLIERS.get(finding.get("category", ""), 1.0)
    return float(weight) * float(multiplier)
```

**File:** `modules/risk_engine.py`, lines 122–127 (`_classify`)

```python
def _classify(normalized_score: int) -> str:
    if normalized_score <= config.RISK_THRESHOLDS["LOW_MAX"]:
        return "LOW"
    if normalized_score <= config.RISK_THRESHOLDS["MEDIUM_MAX"]:
        return "MEDIUM"
    return "HIGH"
```

**Supporting constants — `config.py`, lines 22–35:**

```python
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
```

*Significance: the formula is `contribution = SEVERITY_WEIGHTS[severity] × CATEGORY_MULTIPLIERS.get(category, 1.0)`, summed across all findings into `raw_score`, normalized via `min(100, round(raw_score / 200 * 100))`, and classified as LOW (≤30), MEDIUM (≤70), or HIGH (>70) — categories not present in `CATEGORY_MULTIPLIERS` (e.g. "Dangerous Permission") default to a neutral ×1.0 multiplier.*

---

### A.7 — `modules/report_generator.py` — the numbered-canvas footer class

**File:** `modules/report_generator.py`, lines 53–86 (`_make_numbered_canvas`, full function including the nested `_NumberedCanvas` class)

```python
def _make_numbered_canvas(generation_stamp: str):
    """Factory that returns a Canvas subclass with the stamp baked in."""

    class _NumberedCanvas(pdfgen_canvas.Canvas):
        """Draws ``Page X of Y`` + generation timestamp on every page."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_pages: list = []

        def showPage(self):
            self._saved_pages.append(dict(self.__dict__))
            super().showPage()

        def save(self):
            total = len(self._saved_pages)
            for idx, state in enumerate(self._saved_pages):
                self.__dict__.update(state)
                self._draw_footer(idx + 1, total)
                super().showPage()
            super().save()

        def _draw_footer(self, page_num: int, total: int) -> None:
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#57606a"))
            self.drawString(2 * cm, 1.2 * cm, f"Page {page_num} of {total}")
            self.drawRightString(
                _PAGE_W - 2 * cm, 1.2 * cm,
                f"Generated: {generation_stamp}",
            )
            self.restoreState()

    return _NumberedCanvas
```

*Significance: `showPage()` is overridden to snapshot the canvas's `__dict__` instead of finalizing the page immediately, so that by the time `save()` runs — when the total page count is finally known — it can replay every saved page state, stamp `Page X of Y` on each one, and only then call the real `showPage()`/`save()`; this two-pass trick is what lets the footer show a correct total without ReportLab supporting forward page-count lookahead natively.*

> **Naming note:** the brief's spec referred to "showPage/_startPage logic." The actual class has no `_startPage` method — the equivalent second-pass redraw logic lives in `save()` (which calls the new helper `_draw_footer()`), not in a method named `_startPage`. If your local copy has a `_startPage` method, that is a refactor that postdates this snapshot; see Part E.

---

## PART B — Chapter 6.4 Database Schema

All statements below are the literal `SCHEMA` list from `modules/db_manager.py`, lines 14–129, in file order. `db_manager.py`'s own docstring (line 1) states: *"Centralised SQLite access for SecureAPK. No raw SQL outside this module."*

### B.1 — `analyses`

```sql
CREATE TABLE IF NOT EXISTS analyses (
    id                     TEXT PRIMARY KEY,
    apk_filename           TEXT NOT NULL,
    apk_path               TEXT NOT NULL,
    apk_hash_sha256        TEXT NOT NULL,
    apk_size_bytes         INTEGER NOT NULL,
    package_name           TEXT,
    app_name               TEXT,
    version_name           TEXT,
    version_code           INTEGER,
    target_sdk             INTEGER,
    min_sdk                INTEGER,
    started_at             TIMESTAMP NOT NULL,
    completed_at           TIMESTAMP,
    status                 TEXT NOT NULL,
    current_phase          INTEGER,
    progress_pct           INTEGER DEFAULT 0,
    error_message          TEXT,
    dynamic_enabled        BOOLEAN NOT NULL,
    sbp_enabled            BOOLEAN NOT NULL,
    educational_enabled    BOOLEAN NOT NULL,
    risk_score             INTEGER,
    risk_classification    TEXT,
    pdf_path               TEXT,
    tool_version           TEXT NOT NULL
)
```

```sql
CREATE INDEX IF NOT EXISTS idx_analyses_started_at ON analyses(started_at DESC)
CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status)
```

- **PK:** `id` (TEXT — a `uuid.uuid4().hex` string, generated in `db_manager.create_analysis`, not an autoincrement integer).
- **Indexes:** `idx_analyses_started_at` (DESC, for the dashboard's most-recent-first listing), `idx_analyses_status`.
- **Post-creation migration:** `_migrate()` (lines 169–173) idempotently runs `ALTER TABLE analyses ADD COLUMN analyst_name TEXT` if the column is absent — this column is *not* in the literal `SCHEMA` list above because it was added after the initial schema was written; cite both the `SCHEMA` list and `_migrate()` if your chapter discusses this column.

### B.2 — `findings`

```sql
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    analysis_id     TEXT NOT NULL,
    phase           INTEGER NOT NULL,
    category        TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    file_location   TEXT,
    line_number     INTEGER,
    code_snippet    TEXT,
    owasp_id        TEXT,
    cwe_id          TEXT,
    pattern_id      TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
)
```

```sql
CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id)
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(analysis_id, severity)
```

- **PK:** `id` (TEXT, UUID hex, supplied by the caller or generated in `save_findings`).
- **FK:** `analysis_id → analyses(id)`, `ON DELETE CASCADE`.
- **Indexes:** `idx_findings_analysis` (single-column), `idx_findings_severity` (composite, analysis_id + severity).

### B.3 — `permissions`

```sql
CREATE TABLE IF NOT EXISTS permissions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL,
    permission_name TEXT NOT NULL,
    is_dangerous    BOOLEAN NOT NULL,
    severity        TEXT,
    description     TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
)
```

```sql
CREATE INDEX IF NOT EXISTS idx_permissions_analysis ON permissions(analysis_id)
```

- **PK:** `id` (INTEGER AUTOINCREMENT — the first of the five child tables to use a surrogate integer key instead of a UUID).
- **FK:** `analysis_id → analyses(id) ON DELETE CASCADE`.

### B.4 — `exported_components`

```sql
CREATE TABLE IF NOT EXISTS exported_components (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL,
    component_type  TEXT NOT NULL,
    component_name  TEXT NOT NULL,
    is_protected    BOOLEAN NOT NULL,
    permission_attr TEXT,
    is_dangerous    BOOLEAN NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
)
```

```sql
CREATE INDEX IF NOT EXISTS idx_exported_analysis ON exported_components(analysis_id)
```

- **PK:** `id` (INTEGER AUTOINCREMENT). **FK:** `analysis_id → analyses(id) ON DELETE CASCADE`.

### B.5 — `runtime_events`

```sql
CREATE TABLE IF NOT EXISTS runtime_events (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id          TEXT NOT NULL,
    event_category       TEXT NOT NULL,
    event_subtype        TEXT,
    log_line             TEXT,
    timestamp_in_session INTEGER,
    severity             TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
)
```

```sql
CREATE INDEX IF NOT EXISTS idx_runtime_analysis ON runtime_events(analysis_id)
```

- **PK:** `id` (INTEGER AUTOINCREMENT). **FK:** `analysis_id → analyses(id) ON DELETE CASCADE`. Populated only when Phase 4 (dynamic analysis) runs.

### B.6 — `sbp_findings`

```sql
CREATE TABLE IF NOT EXISTS sbp_findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id         TEXT NOT NULL,
    sbp_rule_id         TEXT NOT NULL,
    rule_name           TEXT NOT NULL,
    compliance_status   TEXT NOT NULL,
    severity            TEXT,
    evidence            TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
)
```

```sql
CREATE INDEX IF NOT EXISTS idx_sbp_analysis ON sbp_findings(analysis_id)
```

- **PK:** `id` (INTEGER AUTOINCREMENT). **FK:** `analysis_id → analyses(id) ON DELETE CASCADE`. One row is written per SBP rule per analysis (`save_sbp_findings`, `db_manager.py` line 465), regardless of compliance status; the risk engine later filters this table for `compliance_status = 'NON_COMPLIANT'` (`get_sbp_findings(analysis_id, status_filter="NON_COMPLIANT")`).

### B.7 — `audit_log`

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL,
    action          TEXT NOT NULL,
    actor           TEXT NOT NULL DEFAULT 'system',
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details         TEXT,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
)
```

```sql
CREATE INDEX IF NOT EXISTS idx_audit_analysis ON audit_log(analysis_id, timestamp)
```

- **PK:** `id` (INTEGER AUTOINCREMENT). **FK:** `analysis_id → analyses(id) ON DELETE CASCADE`. **Index:** composite `(analysis_id, timestamp)`, supporting the chronological chain-of-custody query used by `forensic.get_chain_of_custody()` and the PDF's Appendix A.

### B.8 — Connection-level invariants (not part of `SCHEMA` itself, but governs all seven tables)

**File:** `modules/db_manager.py`, lines 145–158

```python
@contextmanager
def _connect():
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        isolation_level=None,  # autocommit
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        conn.close()
```

*Significance: `PRAGMA foreign_keys = ON` is set on every connection, which is what makes the `ON DELETE CASCADE` clauses above actually take effect — SQLite ignores foreign-key constraints by default unless this pragma is issued per-connection; `isolation_level=None` puts the connection in autocommit mode; `sqlite3.Row` lets calling code do dict-like column access (`row["package_name"]`).*

---

## PART C — Chapter 6.2 Testing Methodology

### C.1 — Real execution result

Command: `.venv/bin/python -m pytest -v --tb=no -q` (run from repo root against this exact checkout, dependencies installed into an isolated virtualenv from `requirements.txt`).

```
platform linux -- Python 3.11.15, pytest-9.1.0, pluggy-1.6.0
collected 53 items

tests/test_app.py ....                                                   [  7%]
tests/test_court_admissible_report.py ....                               [ 15%]
tests/test_db_manager.py ...                                             [ 20%]
tests/test_dynamic_analyzer.py ......                                    [ 32%]
tests/test_educational.py ..                                             [ 35%]
tests/test_forensic.py ...                                               [ 41%]
tests/test_manifest_analyzer.py ......                                   [ 52%]
tests/test_orchestrator.py ..                                            [ 56%]
tests/test_performance.py .                                              [ 58%]
tests/test_report_generator.py ......                                    [ 69%]
tests/test_risk_engine.py ....                                           [ 77%]
tests/test_sbp_compliance.py ....                                        [ 84%]
tests/test_source_analyzer.py ........                                  [100%]

53 passed in 6.99s
```

**Result: 53 / 53 passed, 0 failed, 0 skipped, 0 errors.** (Wall time varies 5.4–7.0s run-to-run on this container; the pass/fail outcome is stable across repeated runs.) No real APK, emulator, or external binary (Jadx/aapt/adb) was required — every test mocks the corresponding subprocess/library call, confirmed by direct inspection of each file's `monkeypatch.setattr(...)` calls.

### C.2 — File-by-file inventory (14 files under `tests/`, 53 test functions total)

| File | Tests | One-line description |
|---|---|---|
| `tests/__init__.py` | 0 | Empty package marker (0 bytes) — makes `tests/` importable, no test content. |
| `tests/conftest.py` | 0 (fixture only) | Defines the shared `tmp_db` fixture: points `db_manager` at a fresh temp SQLite file for the duration of a test, then resets the override on teardown. Also inserts the repo root onto `sys.path`. |
| `tests/test_app.py` | 4 | Phase 12 Flask route tests: `/api/health/adb` with and without a detected emulator, CSRF token present on the upload page, and that `/dashboard` calls the single-query `list_analyses_with_counts()` rather than N+1 `get_findings()` calls. |
| `tests/test_court_admissible_report.py` | 4 | Phase 11 forensic-PDF tests: SHA-256 visible in the first 30% of PDF bytes, a "Chain of Custody" appendix present with a timestamp count ≥ the audit-log row count, every timestamp in the PDF is ISO 8601 with an explicit `+HH:MM`/`-HH:MM` offset (no naive timestamps leak through), and every page carries a `Page X of Y` footer. |
| `tests/test_db_manager.py` | 3 | Schema/CRUD tests: all seven tables exist after `init_db()`, `create_analysis`/`get_analysis` round-trips correctly, and deleting an `analyses` row cascades to its `findings`/`audit_log` children via the FK `ON DELETE CASCADE`. |
| `tests/test_dynamic_analyzer.py` | 6 | Phase 4 ADB-pipeline tests (all ADB calls mocked): full pipeline success with canned logcat text producing `CLEARTEXT_HTTP`/`CREDENTIAL_LOG_EXPOSURE`/`SSL_VALIDATION_EXCEPTION` events + matching findings + confirmed install/uninstall calls; no-emulator path returns `skipped_no_emulator` without raising; install timeout returns `skipped_install_failed` without ever starting logcat; the logcat classifier tags a `CleartextTraffic` line as `CLEARTEXT_HTTP`/HIGH; the 10-category runtime-event catalog has exactly 10 unique ids; and (Phase 12) the monkey command's event-count argument comes from `config.DYNAMIC_MONKEY_EVENT_COUNT`, not a hardcoded literal. |
| `tests/test_educational.py` | 2 | Phase 8 tests: every `VULN_PATTERNS` entry has a complete `remediation` dict (re-asserted here as Phase 8's own contract), and `educational.get_remediation_for_finding` returns the correct remediation dict for a known finding while returning `None` for an unknown finding id, a finding with no `pattern_id`, and a finding whose `pattern_id` isn't in the catalog. |
| `tests/test_forensic.py` | 3 | Phase 6 forensic-helper tests: `compute_sha256` matches `hashlib.sha256` on the same bytes, `forensic.audit()` writes exactly one matching row to `audit_log` with `actor='system'` and a populated timestamp, and three sequential audit entries (with short sleeps to force sub-second ordering) come back in strict chronological order. |
| `tests/test_manifest_analyzer.py` | 6 | Phase 2 tests: PyAXMLParser succeeds on a (real, if present, else mocked) APK and correctly flags `READ_SMS` as the one dangerous permission out of two requested; fallback to `aapt` when PyAXMLParser raises, parsing package/version/SDK/permissions from canned `aapt dump badging` text; final fallback to raw DEX/ZIP string extraction when both prior tiers fail, still recovering package name and dangerous permissions; detection of `android:debuggable="true"` as a HIGH/M7 finding; detection of an unprotected exported activity and an implicit-intent-filter receiver as MEDIUM/M8 findings while a permission-protected exported service is correctly excluded; and a catalog sanity check that `DANGEROUS_PERMISSIONS` has ≥ 37 entries. |
| `tests/test_orchestrator.py` | 2 | Phase 9 end-to-end tests with manifest/source analyzers patched to canned dicts: the happy path confirms `status='completed'`, a populated risk score/classification, a generated PDF on disk, and the full expected audit-log action sequence including `phase_5_completed` occurring strictly after both `phase_3_completed` and `phase_7_completed`; the failure path (manifest analyzer raises) confirms `status='failed'`, a populated `error_message`, no PDF, no risk classification, and that no `phase_*_completed` audit entries were written after the failure point. |
| `tests/test_performance.py` | 1 | Phase 9 benchmark: a synthetic ~2000-record APK payload must complete Phase 2 + Phase 3 combined in under 60 seconds, printing the actual elapsed time on success or failure for diagnosability, and asserting both phases actually produced a recognised `parser_used`/`decompiler_used` value (guards against a false-pass from doing no work). |
| `tests/test_report_generator.py` | 6 | Phase 6 + Phase 12 PDF tests: a generated PDF exists, is > 1000 bytes, and starts with the `%PDF-` signature; the cover page contains the APK's SHA-256 hash verbatim and that hash round-trips against a fresh `hashlib.sha256` of the same bytes; every finding's title string appears somewhere in the PDF body and the seeded DB has exactly 3 findings; two consecutive regenerations of the same completed analysis are byte-identical (forensic-reproducibility guarantee, not in the original required list but backs an ARCHITECTURE.md acceptance criterion); the PDF contains "Executive Summary", "Severity Distribution", "Scope and Limitations", and "Conclusion and Recommendations" section headers (Phase 12); and the methodology paragraph cites the exact dynamic `len(VULN_PATTERNS)` count rather than a hardcoded number. |
| `tests/test_risk_engine.py` | 4 | Phase 5 tests: zero findings produce `raw_score=0`, `normalized_score=0`, classification `LOW`, and all-empty aggregation lists; 12 HIGH findings in the ×1.5 "Hardcoded Secrets" category produce `raw_score=180`, normalized `90`, classification `HIGH`, with `M1`/`CWE-798` present in the triggered lists; a mixed-severity, mixed-category set of 4 findings normalizes to a score inside `0..100` with the highest-weighted category (`Insecure Communication`, ×1.4) sorted first in `top_issues`; and `breakdown_by_phase`'s four bucket values (`manifest`+`source`+`dynamic`+`sbp`) sum exactly to `raw_score` across a 6-finding, 4-phase mixed set, with every bucket non-zero. |
| `tests/test_sbp_compliance.py` | 4 | Phase 7 tests: the banking-app heuristic flags a JazzCash-style package/app-name as a banking app (and correctly does *not* flag Spotify); a manifest with `usesCleartextTraffic=true` trips SBP rule `SBP-CSF-3.2.1` as `NON_COMPLIANT`/HIGH with "cleartext" in the evidence string, and that rule also surfaces as a Phase-7 finding; SBP findings are completely absent from the DB and from the analysis-detail page's `data-tab="sbp"` markup when `sbp_enabled=False`; and a catalog sanity check that `SBP_RULES` has ≥ 10 entries with unique ids. |
| `tests/test_source_analyzer.py` | 8 | Phase 3 tests: a stubbed Jadx run on one Java file containing both a Google API key and an HTTP URL literal produces ≥ 2 findings, each carrying the correct `file_location`/`line_number`/`phase=3`; a hardcoded Google API key pattern is detected with severity HIGH, category "Hardcoded Secrets", `owasp_id="M1"`, `cwe_id="CWE-798"`; `MessageDigest.getInstance("MD5")` is detected as `WEAK_HASH_MD5`/HIGH/"Weak Cryptography"; when Jadx is unavailable, the DEX-string fallback still recovers both the API-key and MD5 patterns from a synthetic `classes.dex` blob, with `file_location="classes.dex"` and `line_number=None` for every finding; the same MD5 pattern repeated 6× in one file plus once more in a second file produces exactly 2 findings (one per file) via per-`(pattern_id, file)` deduplication; every entry in `VULN_PATTERNS` has a non-empty `remediation` dict with all three required keys (Phase 8 contract, re-checked here); `VULN_PATTERNS` has ≥ 30 entries spanning exactly the 9 declared `CATEGORIES`; and every pattern's `regex` field compiles without raising `re.error`. |

**Per-file test counts** (sum = 53, matches the collected total): `test_app.py`=4, `test_court_admissible_report.py`=4, `test_db_manager.py`=3, `test_dynamic_analyzer.py`=6, `test_educational.py`=2, `test_forensic.py`=3, `test_manifest_analyzer.py`=6, `test_orchestrator.py`=2, `test_performance.py`=1, `test_report_generator.py`=6, `test_risk_engine.py`=4, `test_sbp_compliance.py`=4, `test_source_analyzer.py`=8.

### C.3 — Cross-cutting catalog-size assertions (sanity checks embedded in the suite, useful for Chapter 7's "scope" framing)

Verified directly via Python introspection against this checkout:

| Catalog | Module | Count | Asserted by |
|---|---|---|---|
| `DANGEROUS_PERMISSIONS` | `modules/patterns/permissions.py` | 37 | `test_manifest_analyzer.py::test_dangerous_permission_catalog_count` (`>= 37`) |
| `VULN_PATTERNS` | `modules/patterns/vuln_patterns.py` | 34 | `test_source_analyzer.py::test_pattern_catalog_size_and_categories` (`>= 30`) |
| `CATEGORIES` (vuln pattern categories) | `modules/patterns/vuln_patterns.py` | 9 | same test, `== 9` |
| `RUNTIME_EVENT_CATEGORIES` | `modules/patterns/runtime_events.py` | 10 | `test_dynamic_analyzer.py::test_runtime_event_categories_count_is_exactly_ten` (`== 10`) |
| `SBP_RULES` | `modules/patterns/sbp_rules.py` | 10 | `test_sbp_compliance.py::test_sbp_rule_pack_has_at_least_ten_rules` (`>= 10`) |

---

## PART D — Chapter 7 Results Data

**Finding: no sample database, sample PDF report, or fixture APK is committed to this repository.** This was confirmed by direct inspection, not inferred:

```
=== database/ ===           => only .gitkeep (0 bytes)
=== reports/ ===             => only .gitkeep (0 bytes)
=== uploads/ ===             => only .gitkeep (0 bytes)
=== tests/fixtures/sample_apks/ === => only .gitkeep (0 bytes) + README.md
```

`git ls-files | grep -E "^(database|reports|uploads)/"` returns only:
```
database/.gitkeep
reports/.gitkeep
uploads/.gitkeep
```

`.gitignore` explicitly excludes `*.db`, `uploads/*` (except `.gitkeep`), `reports/*` (except `.gitkeep`), and `database/*` (except `.gitkeep`) — this is a **deliberate design choice**, not data loss or an oversight. `tests/fixtures/sample_apks/README.md` independently states the same policy for APKs: *"Do NOT commit APK binaries... Always re-download fresh from the upstream source,"* listing three recommended sources (DIVA, InsecureShop, AndroGoat) by upstream GitHub URL.

**Consequence for Chapter 7:** there is no committed risk score, no committed finding-count breakdown by severity, and no committed phase-by-phase score breakdown anywhere in this repository to extract. **Do not invent or estimate these numbers.** Any numeric results table for Chapter 7 (risk score, HIGH/MEDIUM/LOW counts, OWASP/CWE categories triggered, phase score breakdown, PDF page count, etc.) must be produced by running a fresh analysis against a real APK — for example, one of the three fixtures named in `tests/fixtures/sample_apks/README.md` — on your own machine with the application actually running (`python app.py`, upload through the web UI or `/upload` route), then reading the resulting row out of `database/secureapk.db` and/or the generated PDF in `reports/`. The test suite (Part C) proves the scoring/reporting *mechanism* is correct via synthetic, hand-constructed findings; it does not — and by design cannot — produce a real-world results dataset, since every test seeds its own throwaway findings rather than analyzing an actual malicious or vulnerable app end to end.

If your newer local working copy already has a `database/secureapk.db` with completed analyses, or saved PDFs under `reports/`, those numbers come from your local environment and are not reproducible from this repo snapshot alone — cite them as your own experimental run, generated on [your date], not as data shipped with the codebase.

---

## PART E — Gap Report (this snapshot vs. the task brief's assumptions)

This section lists every item the task brief referenced that this repository checkout does **not** contain, so you know exactly where this snapshot may differ from your newer local working copy.

1. **`modules/androguard_analyzer.py` does not exist.** No file by that name (or similar) under `modules/`. No import of it anywhere (`modules/analyzer.py`'s import block lists exactly 8 sibling modules, none androguard-based). No `androguard` entry in `requirements.txt`. No repo-wide reference to `androguard.misc.AnalyzeAPK`, `AnalyzeAPK`, or `AndroguardAnalyzer`. The only repo-tracked occurrence of the string "androguard" is a single parenthetical in `CLAUDE (4).md` line 52 justifying the choice of Python as the implementation language — it is not a reference to working code. (Numerous incidental matches for "androguard" also appear inside `.venv/lib/python3.11/site-packages/pyaxmlparser/...` — these are internal docstrings/comments belonging to the third-party `pyaxmlparser` package's own dependency chain, not part of this project's code, and `.venv/` is gitignored.) **If you've added bytecode analysis via androguard locally since this snapshot, Part A.5 above cannot stand in for it — pull that listing from your local file directly.**

2. **No "deep bytecode" toggle exists anywhere in the stack.** Checked at every layer: the `AnalysisOptions` dataclass (`modules/analyzer.py` lines 20–24, exactly 3 fields), the `analyses` table schema (Part B.1, exactly 3 boolean columns: `dynamic_enabled`, `sbp_enabled`, `educational_enabled`), the Flask upload route (`app.py` lines 57–60, exactly 3 `request.form.get(...)` calls), and the upload template (`templates/index.html` lines 73/83/92, exactly 3 `<input type="checkbox">` elements). There is no fourth toggle, no hidden config flag, and no UI stub for one.

3. **Phases stop at 12; there is no Phase 13+.** `PHASES (5).md` contains exactly twelve `## Phase N —` headers (Phase 1 Foundation through Phase 12 "Polish, Dynamic Analysis UX, Report Enhancement, UI/UX Overhaul"). If bytecode/deep-scan analysis is planned as a future phase in your local roadmap, it postdates this document.

4. **No sample database, PDF, or fixture APK is committed** (detailed in Part D) — this is by deliberate `.gitignore` policy, documented in-repo via `tests/fixtures/sample_apks/README.md`, not a missing/broken feature.

5. **Minor naming mismatch in the PDF canvas class** (Part A.7): the brief expected "`showPage`/`_startPage` logic"; the actual `_NumberedCanvas` class has `__init__`/`showPage`/`save`/`_draw_footer` — there is no `_startPage` method in this snapshot. If your local copy has refactored this into a `_startPage` method, cite that local version instead.

6. **`analyst_name` column is a migration, not part of the original schema literal.** It's added to `analyses` via `_migrate()` (`db_manager.py` lines 169–173) rather than appearing in the `SCHEMA` list (lines 14–129) itself. Both are quoted in Part B.1 so the chapter can describe it accurately either way.

No other items from the task brief were found missing — `analyzer.py`, `manifest_analyzer.py`, `source_analyzer.py`, `dynamic_analyzer.py`, `risk_engine.py`, `report_generator.py`, and all seven requested database tables are present, complete, and exercised by passing tests, as quoted verbatim in Parts A–C above.
