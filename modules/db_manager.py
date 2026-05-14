"""Centralised SQLite access for SecureAPK. No raw SQL outside this module."""
from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import config


SCHEMA = [
    """
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
    """,
    "CREATE INDEX IF NOT EXISTS idx_analyses_started_at ON analyses(started_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status)",
    """
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
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(analysis_id, severity)",
    """
    CREATE TABLE IF NOT EXISTS permissions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id     TEXT NOT NULL,
        permission_name TEXT NOT NULL,
        is_dangerous    BOOLEAN NOT NULL,
        severity        TEXT,
        description     TEXT,
        FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_permissions_analysis ON permissions(analysis_id)",
    """
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
    """,
    "CREATE INDEX IF NOT EXISTS idx_exported_analysis ON exported_components(analysis_id)",
    """
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
    """,
    "CREATE INDEX IF NOT EXISTS idx_runtime_analysis ON runtime_events(analysis_id)",
    """
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
    """,
    "CREATE INDEX IF NOT EXISTS idx_sbp_analysis ON sbp_findings(analysis_id)",
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id     TEXT NOT NULL,
        action          TEXT NOT NULL,
        actor           TEXT NOT NULL DEFAULT 'system',
        timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        details         TEXT,
        FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_analysis ON audit_log(analysis_id, timestamp)",
]


_DB_PATH_OVERRIDE: Path | None = None


def set_db_path(path: Path | str | None) -> None:
    """Test hook: override the database path. Pass None to reset."""
    global _DB_PATH_OVERRIDE
    _DB_PATH_OVERRIDE = Path(path) if path is not None else None


def _db_path() -> Path:
    return _DB_PATH_OVERRIDE if _DB_PATH_OVERRIDE is not None else config.DATABASE_PATH


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


def init_db() -> None:
    """Create all tables and indexes if they don't exist."""
    with _connect() as conn:
        for stmt in SCHEMA:
            conn.execute(stmt)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- analyses ----------

def create_analysis(
    apk_filename: str,
    apk_path: str,
    apk_hash_sha256: str,
    apk_size_bytes: int,
    dynamic_enabled: bool,
    sbp_enabled: bool,
    educational_enabled: bool,
    tool_version: str,
) -> str:
    analysis_id = uuid.uuid4().hex
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO analyses (
                id, apk_filename, apk_path, apk_hash_sha256, apk_size_bytes,
                started_at, status, progress_pct,
                dynamic_enabled, sbp_enabled, educational_enabled, tool_version
            ) VALUES (?, ?, ?, ?, ?, ?, 'running', 0, ?, ?, ?, ?)
            """,
            (
                analysis_id, apk_filename, apk_path, apk_hash_sha256, apk_size_bytes,
                _now(), int(dynamic_enabled), int(sbp_enabled), int(educational_enabled),
                tool_version,
            ),
        )
    return analysis_id


def get_analysis(analysis_id: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return dict(row) if row else None


def list_analyses() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM analyses ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]


def set_current_phase(analysis_id: str, phase: int) -> None:
    with _connect() as conn:
        conn.execute("UPDATE analyses SET current_phase = ? WHERE id = ?", (phase, analysis_id))


def set_progress(analysis_id: str, pct: int) -> None:
    with _connect() as conn:
        conn.execute("UPDATE analyses SET progress_pct = ? WHERE id = ?", (pct, analysis_id))


def mark_completed(analysis_id: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE analyses SET status = 'completed', completed_at = ?, progress_pct = 100, current_phase = NULL WHERE id = ?",
            (_now(), analysis_id),
        )


def mark_failed(analysis_id: str, error_message: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE analyses SET status = 'failed', completed_at = ?, error_message = ? WHERE id = ?",
            (_now(), error_message, analysis_id),
        )


def set_apk_path(analysis_id: str, apk_path: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE analyses SET apk_path = ? WHERE id = ?", (apk_path, analysis_id))


def delete_analysis(analysis_id: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))


# ---------- findings ----------

def save_findings(analysis_id: str, findings: Iterable[dict[str, Any]]) -> None:
    with _connect() as conn:
        for f in findings:
            conn.execute(
                """
                INSERT INTO findings (
                    id, analysis_id, phase, category, severity, title, description,
                    file_location, line_number, code_snippet, owasp_id, cwe_id, pattern_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.get("id") or uuid.uuid4().hex,
                    analysis_id,
                    f["phase"],
                    f["category"],
                    f["severity"],
                    f["title"],
                    f["description"],
                    f.get("file_location"),
                    f.get("line_number"),
                    f.get("code_snippet"),
                    f.get("owasp_id"),
                    f.get("cwe_id"),
                    f.get("pattern_id"),
                ),
            )


def get_findings(analysis_id: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE analysis_id = ? ORDER BY phase, severity", (analysis_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_finding(finding_id: str) -> dict[str, Any] | None:
    """Look up a single finding by its UUID id. Used by educational lookups."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,),
        ).fetchone()
        return dict(row) if row else None


# ---------- manifest metadata / permissions / exported components ----------

def save_manifest_metadata(analysis_id: str, manifest: dict[str, Any]) -> None:
    with _connect() as conn:
        conn.execute(
            """
            UPDATE analyses
               SET package_name = ?, app_name = ?, version_name = ?, version_code = ?,
                   target_sdk = ?, min_sdk = ?
             WHERE id = ?
            """,
            (
                manifest.get("package_name"),
                manifest.get("app_name"),
                manifest.get("version_name"),
                manifest.get("version_code"),
                manifest.get("target_sdk"),
                manifest.get("min_sdk"),
                analysis_id,
            ),
        )


def save_permissions(analysis_id: str, permissions: Iterable[dict[str, Any]]) -> None:
    with _connect() as conn:
        for p in permissions:
            conn.execute(
                """
                INSERT INTO permissions
                    (analysis_id, permission_name, is_dangerous, severity, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    p["name"],
                    int(bool(p.get("is_dangerous"))),
                    p.get("severity"),
                    p.get("description"),
                ),
            )


def get_permissions(analysis_id: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM permissions WHERE analysis_id = ? ORDER BY is_dangerous DESC, permission_name",
            (analysis_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def save_exported_components(analysis_id: str, components: Iterable[dict[str, Any]]) -> None:
    with _connect() as conn:
        for c in components:
            conn.execute(
                """
                INSERT INTO exported_components
                    (analysis_id, component_type, component_name, is_protected,
                     permission_attr, is_dangerous)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    c.get("type") or c.get("component_type"),
                    c.get("name") or c.get("component_name"),
                    int(bool(c.get("is_protected"))),
                    c.get("permission_attr"),
                    int(bool(c.get("is_dangerous"))),
                ),
            )


def get_exported_components(analysis_id: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM exported_components WHERE analysis_id = ? ORDER BY component_type, component_name",
            (analysis_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def set_parser_used(analysis_id: str, parser_used: str) -> None:
    """Record which manifest parser activated. Stored alongside audit log
    rather than in analyses (no dedicated column — matches §4 schema as-is)."""
    add_audit_entry(analysis_id, "manifest_parser", details=parser_used)


# ---------- runtime events (Phase 4) ----------

def save_runtime_events(analysis_id: str, events: Iterable[dict[str, Any]]) -> None:
    with _connect() as conn:
        for e in events:
            conn.execute(
                """
                INSERT INTO runtime_events
                    (analysis_id, event_category, event_subtype, log_line,
                     timestamp_in_session, severity)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    e.get("category") or e.get("event_category"),
                    e.get("subtype") or e.get("event_subtype"),
                    e.get("log_line"),
                    e.get("timestamp_in_session"),
                    e.get("severity"),
                ),
            )


def get_runtime_events(analysis_id: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM runtime_events WHERE analysis_id = ? "
            "ORDER BY timestamp_in_session, id",
            (analysis_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- risk (Phase 5) ----------

def save_risk(analysis_id: str, risk: dict[str, Any]) -> None:
    """Persist the normalized score + classification on the analyses row."""
    with _connect() as conn:
        conn.execute(
            "UPDATE analyses SET risk_score = ?, risk_classification = ? WHERE id = ?",
            (risk.get("normalized_score"), risk.get("classification"), analysis_id),
        )


def set_pdf_path(analysis_id: str, pdf_path: str) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE analyses SET pdf_path = ? WHERE id = ?", (pdf_path, analysis_id),
        )


# ---------- SBP compliance (Phase 7) ----------

def save_sbp_findings(analysis_id: str, rule_results: Iterable[dict[str, Any]]) -> None:
    """Persist one row per SBP rule (any status). The risk engine pulls
    NON_COMPLIANT rows back out via get_sbp_findings(status='NON_COMPLIANT')."""
    with _connect() as conn:
        for r in rule_results:
            conn.execute(
                """
                INSERT INTO sbp_findings
                    (analysis_id, sbp_rule_id, rule_name, compliance_status,
                     severity, evidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    r["rule_id"],
                    r["name"],
                    r["compliance_status"],
                    r.get("severity"),
                    r.get("evidence"),
                ),
            )


def get_sbp_findings(analysis_id: str, status_filter: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT * FROM sbp_findings WHERE analysis_id = ?"
    params: tuple[Any, ...] = (analysis_id,)
    if status_filter:
        sql += " AND compliance_status = ?"
        params += (status_filter,)
    sql += " ORDER BY sbp_rule_id"
    with _connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


# ---------- audit log ----------

def add_audit_entry(analysis_id: str, action: str, actor: str = "system", details: str | None = None) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO audit_log (analysis_id, action, actor, details) VALUES (?, ?, ?, ?)",
            (analysis_id, action, actor, details),
        )


def get_audit_log(analysis_id: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE analysis_id = ? ORDER BY timestamp, id", (analysis_id,)
        ).fetchall()
        return [dict(r) for r in rows]
