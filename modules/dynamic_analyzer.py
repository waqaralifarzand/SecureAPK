"""Phase 4 - automated runtime analysis via ADB.

Pipeline (ARCHITECTURE.md sec 10 fallback chain):

    1. adb devices                                            -> detect emulator
    2. adb install -r -t <apk>                                -> install
    3. adb shell monkey -p <pkg> -c LAUNCHER 1                -> launch app
    4. sleep 3s                                               -> let app settle
    5. adb logcat -v time  (Popen, terminated after Tcfg)     -> capture
    6. adb shell dumpsys package <pkg>                        -> snapshot perms
    7. adb uninstall <pkg>                                    -> ALWAYS in finally

Failure handling (this is what broke the original implementation):

    * No emulator                  -> status="skipped_no_emulator", no exception
    * adb install timeout/failure  -> status="skipped_install_failed"
    * Launch fails after install   -> status="partial" with whatever events
                                       were captured up to that point
    * Anything else                -> status="partial", error logged to audit

`analyze()` NEVER raises into the orchestrator.

CLAUDE.md sec 6 rules honoured:
    * No Frida / Xposed / dynamic instrumentation - ADB + logcat + monkey only
    * APK is always uninstalled (finally block)
    * SAFETY: never run real malware here. Test only with intentionally-
      vulnerable APKs from documented sources (DIVA, InsecureShop, AndroGoat).
    * Module-level threading.Lock serialises ADB access (sec 8 - one
      emulator, one analysis at a time).
"""
from __future__ import annotations

import logging
import os
import re
import signal
import subprocess
import threading
import time
import uuid
from typing import Any

import config
from modules.patterns.runtime_events import RUNTIME_EVENT_CATEGORIES

log = logging.getLogger(__name__)


# Sec 8: serialise all ADB calls. One emulator => one analysis at a time.
_ADB_LOCK = threading.Lock()


def _adb() -> str:
    return config.ADB_PATH or "adb"


# --------------------------------------------------------------------------
# Public entry point - never raises into the orchestrator.
# --------------------------------------------------------------------------

def analyze(apk_path: str, package_name: str | None) -> dict[str, Any]:
    """Run dynamic analysis against the configured emulator. Never raises.

    Returns a `DynamicAnalysisResult` dict per ARCHITECTURE.md sec 6.
    """
    if not package_name:
        return _result(
            status="skipped_no_package",
            status_message=("No package name was extracted in Phase 2. "
                            "Dynamic analysis cannot proceed without it."),
        )

    with _ADB_LOCK:
        return _run_pipeline(apk_path, package_name)


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

        # 3. Launch via monkey ------------------------------------------
        try:
            _run([adb, "-s", emulator, "shell", "monkey", "-p", package_name,
                  "-c", "android.intent.category.LAUNCHER",
                  str(config.DYNAMIC_MONKEY_EVENT_COUNT)], timeout=60)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            log.warning("monkey launch failed for %s: %s", package_name, e)
            status = "partial"
            status_message = "App was installed but failed to launch via monkey."

        # 4. Settle, then 5. logcat capture ------------------------------
        time.sleep(3)
        capture_duration = (config.DYNAMIC_LOGCAT_DURATION_SECONDS
                            + config.DYNAMIC_LOGCAT_SETTLE_SECONDS)
        logs, logcat_seconds = _capture_logcat(adb, emulator, capture_duration)
        events = _classify_logcat(logs, package_name)

        # 6. Best-effort permission snapshot - failure is non-fatal.
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


# --------------------------------------------------------------------------
# Step helpers
# --------------------------------------------------------------------------

def _detect_emulator(adb: str) -> str | None:
    """Return the first online device id, or None if `adb` is missing/empty."""
    try:
        proc = subprocess.run(
            [adb, "devices"], capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        log.info("adb devices unavailable: %s", e)
        return None
    if proc.returncode != 0:
        return None
    # Lines after the header: "<id>\tdevice"
    for line in proc.stdout.splitlines()[1:]:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            return parts[0]
    return None


def _run(cmd: list[str], *, timeout: int) -> subprocess.CompletedProcess:
    """Wrapper that raises CalledProcessError on non-zero exit."""
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, proc.stdout, proc.stderr,
        )
    return proc


def _capture_logcat(adb: str, emulator: str, duration: int) -> tuple[str, int]:
    """Stream `adb logcat -v time` for `duration` seconds, then terminate.

    Uses Popen + a process group on Unix so the child tree dies together.
    Returns (combined stdout, actual elapsed seconds).
    """
    cmd = [adb, "-s", emulator, "logcat", "-v", "time"]

    started = time.monotonic()
    popen_kwargs: dict[str, Any] = dict(
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except (FileNotFoundError, OSError) as e:
        log.warning("logcat Popen failed: %s", e)
        return "", 0

    try:
        time.sleep(duration)
    finally:
        _terminate(proc)

    try:
        stdout, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()

    return (stdout or ""), int(time.monotonic() - started)


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        proc.terminate()
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        proc.terminate()


# --------------------------------------------------------------------------
# Logcat classification
# --------------------------------------------------------------------------

# Compile every category's patterns once at module load. Keeping them in
# `RUNTIME_EVENT_CATEGORIES` order so first-match wins reproducibly.
_COMPILED: list[tuple[dict, list[re.Pattern[str]]]] = [
    (cat, [re.compile(p) for p in cat["logcat_patterns"]])
    for cat in RUNTIME_EVENT_CATEGORIES
]


def _classify_logcat(logs: str, package_name: str | None) -> list[dict[str, Any]]:
    """Walk every logcat line; emit at most one event per (category, line)."""
    events: list[dict[str, Any]] = []
    if not logs:
        return events

    seen_dedup: dict[tuple[str, str], dict[str, Any]] = {}
    started = time.monotonic()

    for raw_line in logs.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for cat, regexes in _COMPILED:
            matched = next((rx for rx in regexes if rx.search(line)), None)
            if not matched:
                continue
            # Collapse identical (category, sub-text) lines into one event
            # with a count so a flood of duplicates doesn't drown the UI.
            dedup_key = (cat["id"], line[:120])
            existing = seen_dedup.get(dedup_key)
            if existing:
                existing["count"] += 1
                continue
            event = {
                "category": cat["name"],
                "category_id": cat["id"],
                "subtype": matched.pattern,
                "log_line": line[:500],
                "timestamp_in_session": int(time.monotonic() - started),
                "severity": cat["severity"],
                "count": 1,
            }
            events.append(event)
            seen_dedup[dedup_key] = event
            # First category wins per line; do not double-classify.
            break

    return events


def _events_to_findings(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Promote each unique (category) into a Phase-4 finding row."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ev in events:
        if ev["category_id"] in seen:
            continue
        seen.add(ev["category_id"])
        findings.append({
            "id": uuid.uuid4().hex,
            "phase": 4,
            "category": ev["category"],
            "severity": ev["severity"],
            "title": f"Runtime event: {ev['category']}",
            "description": (
                f"Detected at runtime in logcat (matched pattern: {ev['subtype']}). "
                f"Sample: {ev['log_line'][:200]}"
            ),
            "file_location": "logcat",
            "line_number": None,
            "code_snippet": ev["log_line"],
            "owasp_id": None,
            "cwe_id": None,
            "pattern_id": ev["category_id"],
        })
    return findings


# --------------------------------------------------------------------------
# Result factory - keeps the DynamicAnalysisResult shape consistent.
# --------------------------------------------------------------------------

def _result(
    *,
    status: str,
    status_message: str,
    emulator_id: str | None = None,
    logcat_duration_seconds: int = 0,
    events: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "status_message": status_message,
        "emulator_id": emulator_id,
        "logcat_duration_seconds": logcat_duration_seconds,
        "events": events or [],
        "findings": findings or [],
    }


def _clip(s: str | None, limit: int = 200) -> str:
    if not s:
        return ""
    s = s.strip()
    return s if len(s) <= limit else s[: limit - 3] + "..."
