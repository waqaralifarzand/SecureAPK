# SCRATCHPAD.md — Session Memory

> **For Claude Code:** This file is the bridge between sessions. **You MUST update this file before closing every phase session** — no exceptions. The next session and the planning chat both rely on it. Append entries; never overwrite existing entries.

> **For Nayab:** This is the running log of what got built, what's pending, and what decisions were made along the way. Use it for viva prep — when a panel asks "why did you do X in phase N?", check the decisions log here.

---

## Quick status

Mirror the boxes from `PHASES.md`. Update when a phase opens (`🔄`) and when its PR merges (`✅`).

| Phase | Status | Started | Completed | PR |
|---|---|---|---|---|
| 1 — Foundation | ⬜ Not started | — | — | — |
| 2 — Manifest Analyzer | ⬜ Not started | — | — | — |
| 3 — Source Code Analyzer | ⬜ Not started | — | — | — |
| 4 — Dynamic Analyzer | ⬜ Not started | — | — | — |
| 5 — Risk Engine + OWASP/CWE | ⬜ Not started | — | — | — |
| 6 — PDF Reports + Forensic | ⬜ Not started | — | — | — |
| 7 — SBP Banking Compliance | ⬜ Not started | — | — | — |
| 8 — Educational Mode | ⬜ Not started | — | — | — |
| 9 — Testing & Polish | ⬜ Not started | — | — | — |

**Running test count:** 0 / 34 target

---

## Repository

- **Repo:** https://github.com/waqaralifarzand/SecureAPK
- **Default branch:** `main`
- **Active branch:** _(set this when a phase session opens)_
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

_Not yet started._

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
