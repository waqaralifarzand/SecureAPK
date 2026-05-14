# SCRATCHPAD.md — Session Memory

> **For Claude Code:** This file is the bridge between sessions. **You MUST update this file before closing every phase session** — no exceptions. The next session and the planning chat both rely on it. Append entries; never overwrite existing entries.

> **For Nayab:** This is the running log of what got built, what's pending, and what decisions were made along the way. Use it for viva prep — when a panel asks "why did you do X in phase N?", check the decisions log here.

---

## Quick status

Mirror the boxes from `PHASES.md`. Update when a phase opens (`🔄`) and when its PR merges (`✅`).

| Phase | Status | Started | Completed | PR |
|---|---|---|---|---|
| 1 — Foundation | ✅ Merged | 2026-05-14 | 2026-05-14 | [#1](https://github.com/waqaralifarzand/SecureAPK/pull/1) |
| 2 — Manifest Analyzer | ✅ Merged | 2026-05-14 | 2026-05-14 | [#2](https://github.com/waqaralifarzand/SecureAPK/pull/2) |
| 3 — Source Code Analyzer | ✅ Merged | 2026-05-14 | 2026-05-14 | [#3](https://github.com/waqaralifarzand/SecureAPK/pull/3) |
| 4 — Dynamic Analyzer | 🔄 PR open | 2026-05-14 | 2026-05-14 | _(see entry below)_ |
| 5 — Risk Engine + OWASP/CWE | ⬜ Not started | — | — | — |
| 6 — PDF Reports + Forensic | ⬜ Not started | — | — | — |
| 7 — SBP Banking Compliance | ⬜ Not started | — | — | — |
| 8 — Educational Mode | ⬜ Not started | — | — | — |
| 9 — Testing & Polish | ⬜ Not started | — | — | — |

**Running test count:** 22 / 34 target

---

## Repository

- **Repo:** https://github.com/waqaralifarzand/SecureAPK
- **Default branch:** `main`
- **Active branch:** `phase-4-dynamic-analyzer` (Phase 4)
- **Local dev URL:** http://127.0.0.1:5000 _(when `python app.py` is running)_

---

## Entry format

When you complete a phase, append an entry to the matching section below using this template. Keep it tight — no fluff. The goal is fast recall, not narrative.

```markdown
### Phase N — [Title]

**Branch:** `phase-N-short-description`
**PR:** [#XX](https://github.com/waqaralifarzand/SecureAPK/pull/XX)
**Completed:** YYYY-MM-DD
**Test count after this phase:** N / 34

**What was built (1-3 sentences):**
Brief factual summary of what the session produced.

**Verified working:**
- Bullet list of acceptance criteria that passed
- Be specific — "DIVA APK upload produces 7 manifest findings" not "manifest analyzer works"

**Pending / deferred:**
- Anything intentionally left for a later phase, with reasoning
- "None" is a valid value here

**Known issues:**
- Bugs, weirdness, or fragile bits worth flagging
- "None" is a valid value here

**Mid-execution decisions:**
- Decisions made during the session that weren't pre-specified in CLAUDE/ARCHITECTURE/PHASES
- Document the *why*, not just the *what*
- "None" is a valid value here

**Files touched:** N files (M added, K modified)

**Next session picks up at:** Phase N+1 — [Title]
```

### Example of a well-written entry

```markdown
### Phase 1 — Foundation

**Branch:** `phase-1-foundation`
**PR:** [#1](https://github.com/waqaralifarzand/SecureAPK/pull/1)
**Completed:** 2026-05-20
**Test count after this phase:** 3 / 34

**What was built:**
Flask app skeleton with all 9 routes from ARCHITECTURE.md §3, SQLite schema with
all 7 tables, upload flow that hashes APKs and creates analysis rows, dashboard
with delete, dark-themed templates using design tokens from CLAUDE.md §5.
Analyzer module exists as a placeholder that marks analyses completed without
running any phase logic.

**Verified working:**
- `python setup.py` exits 0 on a clean checkout, creates DB and folders
- `python app.py` boots on 127.0.0.1:5000
- Uploading test.apk creates analyses row, saves file to uploads/, computes SHA-256
- Result page polls status and refreshes when analyzer placeholder completes
- Dashboard delete cascades correctly (no orphaned findings/permissions)
- `/health` returns valid JSON with all four flags
- pytest exits 0 with 3 passing tests in test_db_manager.py

**Pending / deferred:**
- None — Phase 1 is complete as scoped.

**Known issues:**
- The "Recent analyses" link on the home page footer is just a hardcoded link;
  no recent-activity widget yet. Acceptable for Phase 1 scope.

**Mid-execution decisions:**
- Used `uuid.uuid4().hex` (no dashes) for analysis_id to keep URLs short.
  Documented in db_manager.py comment.
- Decided `MAX_UPLOAD_SIZE_MB` validation rejects oversized uploads with a 413
  response rather than truncating — matches Flask's default behavior.

**Files touched:** 18 files added, 0 modified.

**Next session picks up at:** Phase 2 — Manifest Analyzer.
```

---

## Phase entries

_Append entries below as phases complete. Do not delete or rewrite earlier entries — they are the project's audit trail._

### Phase 1 — Foundation

**Branch:** `phase-1-foundation`
**PR:** [#1](https://github.com/waqaralifarzand/SecureAPK/pull/1)
**Completed:** 2026-05-14
**Test count after this phase:** 3 / 34

**What was built:**
Bootable Flask app with the full HTTP surface from ARCHITECTURE.md §3 (all 9
routes), a centralised `db_manager` that owns the 7-table SQLite schema
verbatim from §4, a placeholder orchestrator `modules/analyzer.py` that runs
in a daemon thread and sleeps ~2s before marking the analysis `completed`,
upload flow that streams the APK to disk, SHA-256-hashes it, and stores the
row, plus dark-themed templates wired to the exact colour tokens from
CLAUDE.md §5. No real analyser logic ships in this phase — Phases 2-8 add it.

**Verified working:**
- `python setup.py` exits 0 on a clean checkout (Python OK, DB created, dirs
  created, Jadx/ADB/emulator probes report missing without failing)
- `python app.py` boots on `127.0.0.1:5000` (HTTP 200 on `/`)
- `/` renders the dark-themed upload page with the three option toggles
- POST `/upload` with a `.apk` file: 302 redirect to `/analysis/<id>`,
  row created in `analyses`, APK saved to `uploads/<analysis_id>.apk`,
  SHA-256 stored — verified that the stored hash equals
  `sha256sum` output for the same file
  (`3397c974d03bf0c5babd252159f365d1badf172ac8555e3fa8196ceb04de0a37`)
- `/analysis/<id>` renders the "Analysis pending — analyzers not yet
  implemented" panel with the APK hash visible, and the page polls
  `/api/analysis/<id>/status` every 2 seconds via `status_poller.js`
- Placeholder orchestrator flips status to `completed` after ~2 seconds;
  `/api/analysis/<id>/status` reflects this and the page reloads
- `/dashboard` lists the analysis; POST `/analysis/<id>/delete` cascades —
  child rows (findings, audit_log) all gone after delete (FK ON DELETE
  CASCADE + `PRAGMA foreign_keys=ON`)
- `/health` returns valid JSON with all four boolean flags
  (`python_ok`, `jadx_ok`, `adb_ok`, `emulator_ok`)
- `pytest tests/test_db_manager.py -v` → 3 passed

**Pending / deferred:**
- All real analysis logic (Phases 2-8). The orchestrator currently iterates
  through every phase number, logs "not implemented", and bumps progress.
- `modules/patterns/` directory is empty but present, ready for Phase 2.

**Known issues:**
- None observed.

**Mid-execution decisions:**
- Used `uuid.uuid4().hex` (no dashes) for `analysis_id` to keep URLs and
  filenames clean.
- Dropped `sqlite3.PARSE_DECLTYPES` from the connection — Python 3.12+
  deprecated the default `TIMESTAMP` converter and stricter splitting on
  ISO-format strings fails. Timestamps are stored and read as plain ISO
  strings instead; this is simpler and removes a deprecation footgun.
- Added `db_manager.set_apk_path()` rather than letting `app.py` issue raw
  SQL, preserving the "no raw SQL outside db_manager" rule.
- Saved uploads under a temporary name then renamed to
  `<analysis_id>.apk` after the DB row is created — keeps filenames aligned
  with analysis IDs for chain-of-custody traceability.

**Files touched:** 25 added, planning .md files renamed (removed " (2)"
suffixes), 14 legacy files deleted per task description.

**Next session picks up at:** Phase 2 — Manifest Analyzer.

### Phase 2 — Manifest Analyzer

**Branch:** `claude/manifest-analyzer-tGGTJ`
**PR:** [#2](https://github.com/waqaralifarzand/SecureAPK/pull/2) (draft)
**Completed:** 2026-05-14
**Test count after this phase:** 9 / 34

**What was built:**
Static manifest analyzer (`modules/manifest_analyzer.py`) with the full
three-step fallback chain from ARCHITECTURE.md §10 — PyAXMLParser →
`aapt dump badging` → raw ZIP/DEX string extraction. Pattern data added in
`modules/patterns/permissions.py` (37 dangerous permissions, count asserted
at import time) and `modules/patterns/owasp_cwe_map.py` (M1-M10 catalog +
manifest-level category mappings). Orchestrator wires Phase 2 in, persists
metadata, permissions, exported components, findings, and records the
chosen parser in `audit_log`. Result page now has the four manifest sections
(metadata, insecure flags, exported components table, findings list) plus
permissions tab and tab-switcher JS. Finding card partial implemented
without educational expansion (deferred to Phase 8 per spec).

**Verified working:**
- `python -m pytest tests/ -v` → **9 passed** (3 Phase 1 + 5 new Phase 2 + 1
  catalog-count sanity check)
- 37 dangerous permissions in `DANGEROUS_PERMISSIONS` — `assert
  len(...) == 37` runs at import time so any future drift fails loudly
- Synthetic-APK upload smoke test (Flask test client):
  - `parser_used = "dex_strings"` (no real binary AXML → primary failed →
    aapt absent → strings fallback fired cleanly — exactly what the chain
    is supposed to do)
  - `package_name = "com.smoke.test"` extracted from DEX strings
  - 2 dangerous permissions persisted (CAMERA, READ_SMS), both HIGH
  - 4 findings persisted (2 perm findings + Backup Allowed MEDIUM +
    Missing NSC LOW)
  - Audit log records: `analysis_started`, `hash_verified`,
    `manifest_parser=dex_strings`, `phase_2_completed`,
    `analysis_completed`
  - Result page renders: tab nav with manifest active by default,
    metadata grid populated, insecure-flags table, exported-components
    section (empty for fallback path - truthful), permissions tab with
    HIGH/MEDIUM/LOW severity badges, 4 finding cards
- `python app.py` boots; `/health` returns valid JSON; `/upload` flow
  end-to-end works
- `parser_used` on smoke-test synthetic APK: `dex_strings` (expected — the
  synthetic APK has no real binary AXML). On a real APK the primary parser
  would activate; drop one into `tests/fixtures/sample_apks/` to exercise.

**Pending / deferred:**
- A real APK fixture (DIVA / InsecureShop) has not been dropped into
  `tests/fixtures/sample_apks/`. Test 1 (`test_pyaxmlparser_parses_valid_apk`)
  uses a `_FakeAPK` monkeypatched for `pyaxmlparser.APK` — when a real APK is
  present the test prefers it automatically.
- The `aapt` fallback parses `aapt dump badging` rather than `xmltree`.
  Badging is easier to regex (key=value pairs) and produces the metadata
  we need; the trade-off is that it does not enumerate components, so the
  exported-components table is empty under that fallback. PyAXMLParser is
  the primary path for real APKs and yields full component data.

**Known issues:**
- None observed within Phase 2 scope.

**Mid-execution decisions:**
- D-1 (see decisions log below): aapt fallback uses `dump badging` not
  `dump xmltree AndroidManifest.xml`. Documented in decisions log.
- D-2: Component `exported` calculation approximates the legacy Android
  default — when `android:exported` is absent we infer `True` iff the
  component has an `intent-filter`. Android 12+ requires the attribute be
  explicit when intent-filters exist; the approximation matches MobSF's
  behaviour and the literature-review's stated rule.
- D-3: `parser_used` is stored as an `audit_log` row
  (`action='manifest_parser', details=<value>`) rather than a new
  `analyses` column. This preserves the §4 schema unchanged and keeps
  the orchestrator's audit-trail-first contract.
- D-4: Used Python's stdlib `xml.etree.ElementTree` in tests to synthesise
  manifest XML trees that match the lxml-Element surface PyAXMLParser
  returns. Avoids depending on a real binary AXML fixture for unit tests
  while still exercising the analyzer's element-walking code.

**Files touched:** 6 added, 5 modified.

**Next session picks up at:** Phase 3 — Source Code Analyzer.

### Phase 3 — Source Code Analyzer

**Branch:** `phase-3-source-analyzer`
**PR:** [#3](https://github.com/waqaralifarzand/SecureAPK/pull/3) (draft)
**Completed:** 2026-05-14
**Test count after this phase:** 17 / 34

**What was built:**
Static source-code analyzer (`modules/source_analyzer.py`) implementing
ARCHITECTURE.md §10's two-step fallback chain — `jadx --no-res --output-dir`
+ per-line regex scan, with a printable-strings sweep of `classes*.dex` as
the safety net when Jadx is absent. Catalog of **34 patterns across exactly
9 categories** lives in `modules/patterns/vuln_patterns.py`; every entry
carries the complete Phase 8 `remediation` dict (vulnerable / fixed /
explanation). Per-(pattern_id, file) deduplication prevents the result page
from flooding when one rule hits on every class. `owasp_cwe_map.py`
extended with the 9 source-code categories. Orchestrator wires Phase 3 in
between Phase 2 and the (still-placeholder) Phase 4. Result page Source
Code tab groups findings by category with file/line info when Jadx ran and
collapses gracefully under the `dex_strings` fallback.

**Verified working:**
- `python -m pytest tests/ -v` → **17 passed** (3 db + 6 manifest + 8 source)
- 34 patterns / 9 categories — `assert len(VULN_PATTERNS) >= 30` and
  `assert {p.category for p} == set(CATEGORIES)` both run at import time
- Synthetic-APK orchestrator smoke test:
  - Phase 2 findings: 3, Phase 3 findings: 2 (Hardcoded Secrets +
    Weak Cryptography), `decompiler_used = "dex_strings"` (no Jadx locally)
  - Audit log records `source_decompiler=dex_strings` and
    `phase_3_completed` with the categories list
  - Result page Source Code tab renders 5 finding cards correctly grouped
    by category (verified via Flask test client)
- Jadx-on-PATH path tested end-to-end via stubbed `subprocess.run`: file
  paths and line numbers come through correctly, dedup is enforced
- DEX-strings fallback test detects HARDCODED_GOOGLE_API_KEY and
  WEAK_HASH_MD5 from a synthesised classes.dex with no Jadx available

**Pattern catalog summary:**
- 5 × Hardcoded Secrets, 4 × Insecure Communication, 5 × Weak Cryptography,
  4 × Insecure Data Storage, 3 × Information Leakage, 3 × WebView Security,
  4 × Code Execution, 3 × IPC Security, 3 × SSL/TLS Validation Bypass
  → 34 total

**Smoke test parser status:**
- Local environment has no `jadx` binary, so the smoke test exercised the
  `dex_strings` fallback. On a host with Jadx installed, the primary path
  activates and findings carry full file/line context.

**Pending / deferred:**
- A real DIVA / InsecureShop APK has not been dropped into
  `tests/fixtures/sample_apks/`. The Jadx-path test uses a `_stub_jadx`
  monkeypatch that builds the .java tree in a temp dir — exercises every
  branch of the analyzer without depending on the external binary.
- Risk scoring (Phase 5) still treats Phase 3 findings as bare rows; the
  risk engine will aggregate them when it lands.

**Known issues:**
- The `HARDCODED_GENERIC_PASSWORD` regex requires the literal token
  `password|passwd|pwd` on the LHS of the assignment. Variants like
  `mPassword`, `userPassword` will still match because of the prefix; if
  it produces too much noise on real APKs in Phase 9 we can tighten with
  `\b`.
- DEX-strings fallback intentionally strips the surrounding quote
  characters during printable extraction. Patterns that match quoted
  literals (e.g. `HTTP_URL_LITERAL`) detect under Jadx but not under the
  fallback. This is expected — fallback coverage is documented as reduced.

**Mid-execution decisions:**
- D-4 (decisions log): Per-(pattern_id, file) dedup uses `break` after the
  first hit per file rather than collecting all hits and dropping later
  duplicates. Saves a regex sweep on long files.
- D-5: Jadx's non-zero exit code is *ignored* if any `.java` files were
  produced on disk. Jadx routinely exits non-zero on partial
  decompilation but still produces usable output; treating the disk
  artefacts as ground truth keeps the analyzer working on the messy
  real-world APKs the literature review highlights.
- D-6: Code snippets under the Jadx path include ±1 surrounding lines
  (stripped of leading/trailing whitespace) to give viva audiences context
  when reviewing a finding without ballooning the DB column. The
  `dex_strings` fallback never has snippets — file/line are absent there.

**Files touched:** 3 added, 4 modified.

**Next session picks up at:** Phase 4 — Dynamic Analyzer (rebuilt from scratch).

### Phase 4 — Dynamic Analyzer

**Branch:** `phase-4-dynamic-analyzer`
**PR:** [#4](https://github.com/waqaralifarzand/SecureAPK/pull/4) (draft)
**Completed:** 2026-05-14
**Test count after this phase:** 22 / 34

**What was built (rebuild from scratch — old `dynamic_analysis.py` was deleted in Phase 1):**
A clean ADB-driven dynamic analyzer (`modules/dynamic_analyzer.py`) that
follows ARCHITECTURE.md §10's full pipeline — `adb devices` → `adb install
-r -t` → `adb shell monkey LAUNCHER 1` → 3-second settle → time-bounded
`adb logcat -v time` capture → optional `dumpsys package` snapshot →
**`adb uninstall` ALWAYS in `finally`**. Every subprocess call has a
timeout; logcat uses `Popen` with a Unix process-group so the child tree
dies together; the whole pipeline runs under a module-level
`threading.Lock` so concurrent uploads can't both grab the emulator
(ARCHITECTURE.md §8). Catalog of **exactly 10 runtime event categories** in
`modules/patterns/runtime_events.py`, count + uniqueness asserted at
import time. Logcat parser deduplicates identical (category, line[:120])
hits with a `count` field — the literature review's "50 identical HTTP
requests collapse to one event" requirement. Orchestrator gates Phase 4
behind `options.dynamic_enabled`; result page Dynamic tab gets a colour-
coded status banner (green/amber/red) that maps `completed` / `partial` /
`skipped_*` to the CLAUDE.md §5 severity tokens.

**Verified working:**
- `python -m pytest tests/ -v` → **22 passed** (3 db + 6 manifest + 8 source + 5 dynamic)
- 10 runtime categories — `assert len(RUNTIME_EVENT_CATEGORIES) == 10` at
  import time; ID uniqueness + severity validity also asserted
- End-to-end no-emulator smoke test through the orchestrator (the most
  common path on a developer laptop):
  - `dynamic_status="skipped_no_emulator"` recorded in `audit_log`
  - `phase_4_completed` logged with `events=0, findings=0, logcat_seconds=0`
  - **Zero exceptions, zero crashes** — orchestrator continued cleanly to
    Phases 5/6 placeholders
  - Result page Dynamic tab rendered the red `banner-skip` banner with the
    "open Android Studio → Device Manager" actionable hint
- Mocked-end-to-end ADB test: install + monkey + logcat (canned output)
  + uninstall all called in order; `adb uninstall <pkg>` confirmed to fire
  in `finally` even after partial failure paths (test 3)
- Logcat classifier correctness: `CleartextTraffic` → `CLEARTEXT_HTTP`
  HIGH; `password=hunter2` → `CREDENTIAL_LOG_EXPOSURE` HIGH;
  `SSLHandshakeException` → `SSL_VALIDATION_EXCEPTION` HIGH

**ADB subprocess approach (this is what broke the original code):**
- `subprocess.run(..., timeout=N, capture_output=True, text=True)` for every
  one-shot ADB call (devices, install, monkey, dumpsys, uninstall)
- `subprocess.Popen(..., preexec_fn=os.setsid)` for logcat, terminated via
  `os.killpg(os.getpgid(pid), SIGTERM)` after `DYNAMIC_LOGCAT_DURATION_SECONDS`
- Windows fallback: `proc.terminate()` instead of `killpg`
- All exceptions caught at the outermost layer; `analyze()` is contract-
  bound to never raise into the orchestrator

**Pending / deferred:**
- Real-emulator validation. We do not have an Android emulator in this
  environment. Nayab should run `python app.py`, start an AVD via Android
  Studio, then upload an APK with Dynamic enabled to confirm the
  `completed` path in addition to the no-emulator path the smoke test
  already covers.
- The `_capture_logcat` helper currently sleeps `duration` seconds in the
  parent and drains stdout via `communicate()` afterwards. For the 30s
  default this is fine; if Phase 9 wants live progress streaming we can
  read stdout in a background thread. Not worth doing pre-Phase-5.

**Known issues:**
- Logcat capture wall time is best-effort. The `logcat_duration_seconds`
  value reported on the result is `int(monotonic delta)` which can be off
  by up to ~1s for a configured 30s window. Acceptable.
- `dumpsys package` failures are intentionally swallowed — it's a
  best-effort permission snapshot, not a blocker.

**Mid-execution decisions:**
- D-7: ADB pipeline returns a *dict* `DynamicAnalysisResult`, not a
  dataclass. Keeps the contract identical to Phases 2 / 3 (manifest /
  source) and lets `db_manager.save_runtime_events` consume the same
  shape that the in-memory pipeline produced.
- D-8: Logcat events that match multiple regex categories are tagged with
  the *first* matching category (in the catalog order from
  ARCHITECTURE.md §11). Prevents double-counting when, e.g., a SSL crash
  line could match both SSL_VALIDATION_EXCEPTION and SECURITY_EXCEPTION_CRASH.
- D-9: Phase 4 stores both `runtime_events` rows AND a `findings` row per
  *unique* category (not per event). Ten distinct categories → at most
  ten Phase 4 finding rows, regardless of how many logcat lines hit each.
  Keeps the result page navigable; the full event table is preserved in
  `runtime_events` for forensic detail.

**Files touched:** 3 added, 5 modified.

**Next session picks up at:** Phase 5 — Risk Engine + OWASP/CWE Mapping.

### Phase 5 — Risk Engine + OWASP/CWE Mapping

_Not yet started._

### Phase 6 — PDF Reports + Forensic Hashing

_Not yet started._

### Phase 7 — SBP Banking Compliance

_Not yet started._

### Phase 8 — Educational Mode

_Not yet started._

### Phase 9 — Testing & Polish

_Not yet started._

---

## Open questions (cross-phase)

Use this section when you encounter something ambiguous mid-phase that needs resolution in the planning chat. Don't guess in the Claude Code session — log it here and surface it next time we talk.

Format:

```markdown
### Q-N: Short question title
**Raised in:** Phase X
**Question:** What needs deciding?
**Why it matters:** What gets blocked or risked if we guess wrong?
**Proposed answer (optional):** Your best guess, if you have one
**Resolution:** _(filled in after the planning chat decides)_
```

_No open questions yet._

---

## Decisions log (mid-execution)

Architectural decisions made *during* execution that weren't pre-specified in CLAUDE.md / ARCHITECTURE.md / PHASES.md. These accumulate over the project lifetime and are the answer to "why was this done this way?" in viva.

Format:

```markdown
### D-N: Short decision title
**Made in:** Phase X
**Date:** YYYY-MM-DD
**Decision:** What was decided
**Reasoning:** Why this over the alternatives
**Reversible?** Easy / Hard / Irreversible
```

### D-1: aapt fallback uses `dump badging`, not `dump xmltree`
**Made in:** Phase 2
**Date:** 2026-05-14
**Decision:** The aapt fallback (level 2 of the manifest fallback chain)
calls `aapt dump badging <apk>` and regex-parses the key=value output,
rather than `aapt dump xmltree <apk> AndroidManifest.xml`.
**Reasoning:** Badging output is line-oriented and trivially regex-parseable
for the metadata we need (package, version, target/min SDK, label,
permissions). xmltree's indentation-based representation requires a
stateful parser and the result is no richer for our purposes.
The trade-off: badging does not enumerate components, so under this
fallback the exported-components section is empty. PyAXMLParser is the
primary parser for any real APK and yields full component data.
**Reversible?** Easy — swap the subprocess args + regexes if Phase 9 finds
that real-world APK robustness needs the xmltree output.

### D-2: Implicit-export heuristic for components without `android:exported`
**Made in:** Phase 2
**Date:** 2026-05-14
**Decision:** A component without an explicit `android:exported` attribute
is treated as exported iff it declares at least one `<intent-filter>` child.
**Reasoning:** This matches the *legacy* Android default (pre-API 31).
API 31+ requires the attribute to be explicit when an intent-filter is
present — but we still encounter older APKs and the legacy rule is what
MobSF and the literature review's referenced rules use. Erring toward
"exported" is also the safer default for a security tool.
**Reversible?** Easy — single conditional in
`manifest_analyzer._component_from_element`.

### D-4: Per-(pattern_id, file) dedup is short-circuit, not post-filter
**Made in:** Phase 3
**Date:** 2026-05-14
**Decision:** When scanning a `.java` file for a given pattern, stop at the
first line that matches and skip the rest. Tracked via a
`seen_keys: set[(pattern_id, file)]` set.
**Reasoning:** Patterns like `printStackTrace()` or `setJavaScriptEnabled(true)`
hit dozens of times in large decompiled outputs. A short-circuit halves the
regex work versus collecting then filtering. The trade-off is that the
saved `line_number` is the *first* hit only — fine for steering a developer
to the file; richer "all hits" reporting can be added in Phase 9 if needed.
**Reversible?** Easy — drop the `break` and post-filter the findings list.

### D-5: Jadx non-zero exit codes are tolerated if .java output exists
**Made in:** Phase 3
**Date:** 2026-05-14
**Decision:** `source_analyzer._analyze_with_jadx` ignores Jadx's exit code
and only raises if **no** `.java` files were produced in the output dir.
**Reasoning:** Jadx returns non-zero whenever any class fails to
decompile — common on real-world APKs that the literature review flags
(obfuscated, multi-dex, signed with newer formats). The disk artefacts are
still usable. Trusting the filesystem over the return code matches what
MobSF and the academic Jadx-wrapper tools do.
**Reversible?** Easy — re-add an `if proc.returncode != 0: raise` check.

### D-7: DynamicAnalysisResult is a plain dict, not a dataclass
**Made in:** Phase 4
**Date:** 2026-05-14
**Decision:** `dynamic_analyzer.analyze()` returns a `dict[str, Any]`
matching the ARCHITECTURE.md §6 shape, not a typed dataclass.
**Reasoning:** Phase 2 (manifest) and Phase 3 (source) already return
dicts; uniformity matters for `db_manager.save_*` helpers and for the
orchestrator's audit-log details. No external consumer needs strong
typing here. If Phase 9 wants type safety we can add a `TypedDict`
without changing any caller.
**Reversible?** Easy — wrap the return in a TypedDict / dataclass.

### D-8: Logcat first-match wins — categories are not multi-tagged
**Made in:** Phase 4
**Date:** 2026-05-14
**Decision:** When a logcat line matches multiple category regexes, only
the *first* category in the catalog order from ARCHITECTURE.md §11 is
emitted as an event.
**Reasoning:** Avoids double-counting (an `SSLException` line could match
both SSL_VALIDATION_EXCEPTION and SECURITY_SENSITIVE_CRASH); makes the
events list deterministic; matches what MobSF's logcat post-processor
does. The catalog order in ARCHITECTURE.md §11 was chosen specifically
so the more specific category comes first.
**Reversible?** Easy — drop the `break` in `_classify_logcat`.

### D-9: One finding per *unique category*, not per event
**Made in:** Phase 4
**Date:** 2026-05-14
**Decision:** `runtime_events` rows preserve the full per-line detail
(with a `count` field collapsing identical lines), but `findings` rows
get one entry per unique `category_id` only.
**Reasoning:** Without this, a chatty cleartext API client could produce
hundreds of HIGH finding cards on the result page. The runtime_events
table still contains the forensic detail; the findings list stays
navigable. Phase 5's risk engine will weight by severity × category — it
doesn't care about per-line counts.
**Reversible?** Easy — change `_events_to_findings` to emit one finding
per event.

### D-6: Source snippets capture ±1 lines of context, stripped
**Made in:** Phase 3
**Date:** 2026-05-14
**Decision:** `code_snippet` includes the matching line plus one line above
and below, joined with `\n` and stripped of leading/trailing whitespace.
**Reasoning:** Single-line snippets are often inscrutable in viva
walkthroughs (the matched line is `return true;` from a hostname
verifier, etc.). Three lines is enough to show the surrounding scope
without bloating the `findings.code_snippet` column. The DEX-strings
fallback never has snippets at all — that's a documented limitation of
the fallback, not a regression.
**Reversible?** Easy — change the `_snippet` helper bounds.

### D-3: `parser_used` recorded in `audit_log`, not in `analyses`
**Made in:** Phase 2
**Date:** 2026-05-14
**Decision:** The chosen manifest parser (`pyaxmlparser` | `aapt` |
`dex_strings`) is persisted as an `audit_log` row
(`action='manifest_parser', details=<value>`) rather than as a new column
on `analyses`.
**Reasoning:** Keeps the §4 schema verbatim — no migration churn — and the
forensic chain-of-custody already wants to capture this kind of state
transition. The result-page renderer reads it back from `audit_log` and
exposes it as `parser_used` on the result view.
**Reversible?** Easy — add an `analyses.parser_used TEXT` column in Phase 9
polish if the audit-log lookup proves clumsy.

---

## Live URLs / Resources

| Resource | URL / Path |
|---|---|
| Local app (when running) | http://127.0.0.1:5000 |
| GitHub repo | https://github.com/waqaralifarzand/SecureAPK |
| GitHub PRs | _(populated as phases ship)_ |
| Test APKs (DIVA) | https://github.com/payatu/diva-android |
| Test APKs (InsecureShop) | https://github.com/hax0rgb/InsecureShop |
| Test APKs (AndroGoat) | https://github.com/satishpatnayak/AndroGoat |
| OWASP MTW10 2024 reference | https://owasp.org/www-project-mobile-top-10/ |
| CWE reference | https://cwe.mitre.org/ |
| Jadx releases | https://github.com/skylot/jadx/releases |

---

*This file is updated by Claude Code at the end of every phase session. Never closed without an update.*
