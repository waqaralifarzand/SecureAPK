# SCRATCHPAD.md — Session Memory

> **For Claude Code:** This file is the bridge between sessions. **You MUST update this file before closing every phase session** — no exceptions. The next session and the planning chat both rely on it. Append entries; never overwrite existing entries.

> **For Nayab:** This is the running log of what got built, what's pending, and what decisions were made along the way. Use it for viva prep — when a panel asks "why did you do X in phase N?", check the decisions log here.

---

## Quick status

Mirror the boxes from `PHASES.md`. Update when a phase opens (`🔄`) and when its PR merges (`✅`).

| Phase | Status | Started | Completed | PR |
|---|---|---|---|---|
| 1 — Foundation | 🔄 PR open | 2026-05-14 | 2026-05-14 | _(see entry below)_ |
| 2 — Manifest Analyzer | ⬜ Not started | — | — | — |
| 3 — Source Code Analyzer | ⬜ Not started | — | — | — |
| 4 — Dynamic Analyzer | ⬜ Not started | — | — | — |
| 5 — Risk Engine + OWASP/CWE | ⬜ Not started | — | — | — |
| 6 — PDF Reports + Forensic | ⬜ Not started | — | — | — |
| 7 — SBP Banking Compliance | ⬜ Not started | — | — | — |
| 8 — Educational Mode | ⬜ Not started | — | — | — |
| 9 — Testing & Polish | ⬜ Not started | — | — | — |

**Running test count:** 3 / 34 target

---

## Repository

- **Repo:** https://github.com/waqaralifarzand/SecureAPK
- **Default branch:** `main`
- **Active branch:** `phase-1-foundation`
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

_Not yet started._

### Phase 3 — Source Code Analyzer

_Not yet started._

### Phase 4 — Dynamic Analyzer

_Not yet started._

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

_No decisions logged yet._

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
