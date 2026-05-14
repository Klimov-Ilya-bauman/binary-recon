"""
Тесты SQLite-хранилища истории.

Используют tmp_path фикстуру pytest — каждый тест получает свежую
временную папку, БД не пересекается между тестами.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_BIN = REPO_ROOT / "core" / "build" / "core"

pytestmark = pytest.mark.skipif(
    not CORE_BIN.is_file() or not os.access(CORE_BIN, os.X_OK),
    reason=f"C++ core not built at {CORE_BIN}",
)


@pytest.fixture
def tmp_db(tmp_path):
    """Свежая БД на время теста."""
    from recon.core.database import Database
    db_path = tmp_path / "test_history.db"
    db = Database(db_path=db_path)
    yield db
    db.close()


@pytest.fixture
def analyzer_with_db(tmp_db):
    """Analyzer, использующий нашу временную БД."""
    from recon.analyzer import Analyzer
    return Analyzer(database=tmp_db, save_to_history=True)


def test_database_creates_schema(tmp_db):
    """Свежесозданная БД содержит все нужные таблицы."""
    tables = {
        row["name"] for row in tmp_db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert "scans" in tables
    assert "findings" in tables


def test_save_and_load_roundtrip(analyzer_with_db, tmp_db):
    """Сохраняем скан, загружаем — данные совпадают."""
    full = analyzer_with_db.analyze("/bin/ls")
    assert full.scan_id is not None

    loaded = tmp_db.load_scan(full.scan_id)
    assert loaded is not None
    assert loaded.analysis.filepath == full.analysis.filepath
    assert loaded.analysis.md5 == full.analysis.md5
    assert loaded.analysis.sha256 == full.analysis.sha256
    assert loaded.risk.score == full.risk.score
    assert loaded.risk.level == full.risk.level


def test_list_scans_orders_by_time(analyzer_with_db, tmp_db):
    """list_scans возвращает в обратном хронологическом порядке."""
    analyzer_with_db.analyze("/bin/ls")
    analyzer_with_db.analyze("/bin/bash")

    scans = tmp_db.list_scans()
    assert len(scans) == 2
    # /bin/bash был последним — должен быть первым в списке
    assert scans[0]["filename"] == "bash"
    assert scans[1]["filename"] == "ls"


def test_filter_by_query(analyzer_with_db, tmp_db):
    """Фильтр по подстроке имени файла работает."""
    analyzer_with_db.analyze("/bin/ls")
    analyzer_with_db.analyze("/bin/bash")

    only_ls = tmp_db.list_scans(query="ls")
    assert len(only_ls) == 1
    assert only_ls[0]["filename"] == "ls"


def test_filter_by_risk_level(analyzer_with_db, tmp_db):
    """Фильтр по risk_level работает."""
    analyzer_with_db.analyze("/bin/ls")  # CLEAN

    cleans = tmp_db.list_scans(risk_levels=["CLEAN"])
    assert len(cleans) == 1
    assert cleans[0]["risk_level"] == "CLEAN"

    highs = tmp_db.list_scans(risk_levels=["HIGH"])
    assert len(highs) == 0


def test_delete_scan(analyzer_with_db, tmp_db):
    """Удаление скана работает и каскадно удаляет findings."""
    full = analyzer_with_db.analyze("/bin/ls")
    assert full.scan_id is not None

    ok = tmp_db.delete_scan(full.scan_id)
    assert ok is True
    assert tmp_db.load_scan(full.scan_id) is None
    assert tmp_db.total_scans() == 0


def test_stats_by_level(analyzer_with_db, tmp_db):
    """stats_by_level считает корректно."""
    analyzer_with_db.analyze("/bin/ls")
    stats = tmp_db.stats_by_level()
    assert stats.get("CLEAN", 0) == 1
