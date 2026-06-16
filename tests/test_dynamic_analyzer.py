"""Phase 4 - Dynamic Analyzer tests.

All ADB interactions are mocked - no real emulator is required.

The four tests required by PHASES.md sec Phase 4:
    1. Successful end-to-end with mocked ADB returning canned logcat
    2. "No emulator" path -> status="skipped_no_emulator", no exception
    3. Install timeout -> status="skipped_install_failed"
    4. Logcat classifier correctly tags a CleartextTraffic line as CLEARTEXT_HTTP

Plus the catalog-count sanity test required by PHASES.md acceptance criteria.
"""
from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from modules import dynamic_analyzer
from modules.patterns.runtime_events import RUNTIME_EVENT_CATEGORIES


# --------------------------------------------------------------------------
# Shared mock helpers
# --------------------------------------------------------------------------

def _devices_with_emulator():
    return SimpleNamespace(
        returncode=0,
        stdout="List of devices attached\nemulator-5554\tdevice\n",
        stderr="",
    )


def _devices_empty():
    return SimpleNamespace(
        returncode=0,
        stdout="List of devices attached\n",
        stderr="",
    )


class _PopenStub:
    """Stand-in for subprocess.Popen returning canned logcat content
    immediately - no real waiting in tests."""
    def __init__(self, stdout: str = ""):
        self._stdout = stdout
        self.pid = 12345
        self._poll = None

    def poll(self):
        return self._poll

    def communicate(self, timeout=None):
        self._poll = 0
        return (self._stdout, "")

    def terminate(self):
        self._poll = 0

    def kill(self):
        self._poll = -9


# Skip the real time.sleep so the suite stays fast.
@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(dynamic_analyzer.time, "sleep", lambda _s: None)


# --------------------------------------------------------------------------
# Test 1 - Successful end-to-end with mocked ADB
# --------------------------------------------------------------------------

def test_full_pipeline_with_mocked_adb(monkeypatch, tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"unused")

    canned_logcat = (
        "01-01 00:00:01.111 D/Net  : http://api.example.com/login was called\n"
        "01-01 00:00:01.222 W/Net  : NetworkSecurityConfig: cleartext rule\n"
        "01-01 00:00:02.000 D/auth : password=hunter2\n"
        "01-01 00:00:03.000 E/X    : javax.net.ssl.SSLHandshakeException: bad cert\n"
    )

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        # adb devices
        if cmd[1:3] == ["devices"]:
            return _devices_with_emulator()
        # everything else: success
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_popen(cmd, **kwargs):
        return _PopenStub(canned_logcat)

    monkeypatch.setattr(dynamic_analyzer.subprocess, "run", fake_run)
    monkeypatch.setattr(dynamic_analyzer.subprocess, "Popen", fake_popen)

    result = dynamic_analyzer.analyze(str(apk), package_name="com.demo.app")

    assert result["status"] == "completed"
    assert result["emulator_id"] == "emulator-5554"
    # We expect at least the cleartext, credential leak, and SSL events
    cat_ids = {ev["category_id"] for ev in result["events"]}
    assert "CLEARTEXT_HTTP" in cat_ids
    assert "CREDENTIAL_LOG_EXPOSURE" in cat_ids
    assert "SSL_VALIDATION_EXCEPTION" in cat_ids
    # And matching Phase-4 findings exist
    assert all(f["phase"] == 4 for f in result["findings"])
    finding_pids = {f["pattern_id"] for f in result["findings"]}
    assert finding_pids >= {"CLEARTEXT_HTTP", "CREDENTIAL_LOG_EXPOSURE",
                            "SSL_VALIDATION_EXCEPTION"}
    # Critical: install + uninstall both happened.
    install_calls = [c for c in calls if "install" in c]
    uninstall_calls = [c for c in calls if "uninstall" in c]
    assert install_calls, "expected adb install"
    assert uninstall_calls, "expected adb uninstall in finally block"


# --------------------------------------------------------------------------
# Test 2 - "No emulator" path returns skipped_no_emulator
# --------------------------------------------------------------------------

def test_no_emulator_returns_skipped_status(monkeypatch, tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"unused")

    def fake_run(cmd, **kwargs):
        if cmd[1:3] == ["devices"]:
            return _devices_empty()
        # Should never reach here on the skip path.
        raise AssertionError(f"unexpected adb call: {cmd}")

    monkeypatch.setattr(dynamic_analyzer.subprocess, "run", fake_run)

    result = dynamic_analyzer.analyze(str(apk), package_name="com.demo.app")

    assert result["status"] == "skipped_no_emulator"
    assert "emulator" in result["status_message"].lower()
    assert result["emulator_id"] is None
    assert result["events"] == []
    assert result["findings"] == []


# --------------------------------------------------------------------------
# Test 3 - Install timeout returns skipped_install_failed
# --------------------------------------------------------------------------

def test_install_timeout_returns_install_failed(monkeypatch, tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"unused")

    def fake_run(cmd, **kwargs):
        if cmd[1:3] == ["devices"]:
            return _devices_with_emulator()
        if "install" in cmd:
            raise subprocess.TimeoutExpired(cmd, 120)
        # uninstall in finally - succeed silently
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dynamic_analyzer.subprocess, "run", fake_run)
    # Popen should not be invoked because install fails before logcat starts.
    monkeypatch.setattr(dynamic_analyzer.subprocess, "Popen",
                        lambda *a, **kw: pytest.fail("logcat must not start after install failure"))

    result = dynamic_analyzer.analyze(str(apk), package_name="com.demo.app")

    assert result["status"] == "skipped_install_failed"
    assert result["emulator_id"] == "emulator-5554"
    assert result["events"] == []


# --------------------------------------------------------------------------
# Test 4 - Logcat classifier tags CleartextTraffic as CLEARTEXT_HTTP
# --------------------------------------------------------------------------

def test_classifier_tags_cleartext_traffic_event():
    log = "01-01 12:00:00.000 W/Net : CleartextTraffic policy violated by app"
    events = dynamic_analyzer._classify_logcat(log, package_name="com.demo.app")

    assert len(events) == 1
    ev = events[0]
    assert ev["category_id"] == "CLEARTEXT_HTTP"
    assert ev["category"] == "Cleartext HTTP Communication"
    assert ev["severity"] == "HIGH"
    assert "CleartextTraffic" in ev["log_line"]


# --------------------------------------------------------------------------
# Catalog sanity check (PHASES.md acceptance criterion 7)
# --------------------------------------------------------------------------

def test_runtime_event_categories_count_is_exactly_ten():
    assert len(RUNTIME_EVENT_CATEGORIES) == 10
    ids = [c["id"] for c in RUNTIME_EVENT_CATEGORIES]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------
# Phase 12: Monkey event count uses config value, not hardcoded "1"
# --------------------------------------------------------------------------

def test_monkey_command_uses_config_event_count(monkeypatch, tmp_path):
    import config
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"unused")

    monkey_cmds: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        if cmd[1:3] == ["devices"]:
            return _devices_with_emulator()
        if "monkey" in cmd:
            monkey_cmds.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_popen(cmd, **kwargs):
        return _PopenStub("")

    monkeypatch.setattr(dynamic_analyzer.subprocess, "run", fake_run)
    monkeypatch.setattr(dynamic_analyzer.subprocess, "Popen", fake_popen)

    dynamic_analyzer.analyze(str(apk), package_name="com.demo.app")

    assert monkey_cmds, "monkey command should have been invoked"
    event_count_arg = monkey_cmds[0][-1]
    assert event_count_arg == str(config.DYNAMIC_MONKEY_EVENT_COUNT), (
        f"expected {config.DYNAMIC_MONKEY_EVENT_COUNT}, got {event_count_arg}"
    )
