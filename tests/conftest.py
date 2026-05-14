"""Shared pytest fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make repo root importable for `import config`, `from modules import ...`.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from modules import db_manager  # noqa: E402


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Point db_manager at a fresh temporary SQLite file for the test."""
    db_file = tmp_path / "test.db"
    db_manager.set_db_path(db_file)
    db_manager.init_db()
    yield db_file
    db_manager.set_db_path(None)
