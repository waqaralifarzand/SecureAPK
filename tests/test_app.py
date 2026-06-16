"""Phase 12 - App route tests: ADB health endpoint, CSRF, dashboard query."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import config
from modules import db_manager


@pytest.fixture
def client(tmp_db, monkeypatch):
    """Flask test client with a fresh DB."""
    monkeypatch.setattr(config, "SECRET_KEY", "test-secret")
    from app import app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as c:
        yield c


@pytest.fixture
def csrf_client(tmp_db, monkeypatch):
    """Flask test client with CSRF enabled."""
    monkeypatch.setattr(config, "SECRET_KEY", "test-secret")
    from app import app
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = True
    with app.test_client() as c:
        yield c


def test_adb_health_endpoint_no_adb(client, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: None)
    resp = client.get("/api/health/adb")
    data = json.loads(resp.data)
    assert resp.status_code == 200
    assert data["adb_installed"] is False
    assert data["emulator_running"] is False
    assert data["emulator_serial"] is None


def test_adb_health_endpoint_with_emulator(client, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/adb")

    def fake_run(cmd, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="List of devices attached\nemulator-5554\tdevice\n",
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)
    resp = client.get("/api/health/adb")
    data = json.loads(resp.data)
    assert data["adb_installed"] is True
    assert data["emulator_running"] is True
    assert data["emulator_serial"] == "emulator-5554"


def test_upload_page_contains_csrf_token(csrf_client):
    resp = csrf_client.get("/")
    assert resp.status_code == 200
    html = resp.data.decode()
    assert 'name="csrf_token"' in html


def test_dashboard_uses_single_query(client, monkeypatch):
    """Verify dashboard calls list_analyses_with_counts (single query),
    not list_analyses + N get_findings calls."""
    call_log = []

    original_with_counts = db_manager.list_analyses_with_counts

    def tracked_with_counts():
        call_log.append("list_analyses_with_counts")
        return original_with_counts()

    def tracked_get_findings(aid):
        call_log.append(f"get_findings:{aid}")
        return []

    monkeypatch.setattr(db_manager, "list_analyses_with_counts", tracked_with_counts)
    monkeypatch.setattr(db_manager, "get_findings", tracked_get_findings)

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "list_analyses_with_counts" in call_log
    assert not any(c.startswith("get_findings:") for c in call_log)
