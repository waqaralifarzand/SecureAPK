# SecureAPK

> Local hybrid static + dynamic security analysis framework for Android APKs.

This is the **Phase 1 — Foundation** build. The Flask app boots, accepts APK
uploads, hashes them, stores rows in SQLite, and renders a dashboard. The real
analysers (manifest, source, dynamic, risk, PDF, SBP, educational) ship in
Phases 2–8. See `PHASES.md`.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate          # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
python setup.py                    # initialises DB + folders, probes Jadx/ADB
python app.py                      # serves on http://127.0.0.1:5000
```

Open `http://127.0.0.1:5000`, drop an `.apk`, watch the placeholder
orchestrator mark the analysis `completed` after about 2 seconds.

## Tests

```bash
pytest -v
```

Phase 1 ships 3 tests (`tests/test_db_manager.py`). Total target by Phase 9 is
34+.

## Project structure

See `ARCHITECTURE.md` §1 for the locked folder layout.

## Planning files

- `CLAUDE.md` — project identity, locked tech stack, design tokens, hard rules.
- `ARCHITECTURE.md` — folder tree, routes, database schema, fallback chains.
- `PHASES.md` — execution roadmap, phase by phase.
- `SCRATCHPAD.md` — running session memory.
