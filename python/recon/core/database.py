"""
Database — SQLite-хранилище истории анализов.

Расположение БД:
  По умолчанию: ~/.recon/history.db
  Переопределение: переменная окружения RECON_DB_PATH

Схема:
  scans     — один скан = одна строка
  findings  — нормализованные findings для SQL-запросов

Полные AnalysisResult и RiskAssessment хранятся как JSON в колонках
raw_json и risk_json — это позволяет восстановить FullAnalysis без
повторного запуска C++ ядра (полезно когда оригинальный файл удалён).
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------- Схема ----------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    filepath        TEXT    NOT NULL,
    filename        TEXT    NOT NULL,
    format          TEXT    NOT NULL,
    arch            TEXT,
    size            INTEGER,
    md5             TEXT,
    sha256          TEXT,
    entropy         REAL,
    risk_score      INTEGER NOT NULL,
    risk_level      TEXT    NOT NULL,
    findings_count  INTEGER NOT NULL,
    raw_json        TEXT    NOT NULL,
    risk_json       TEXT    NOT NULL,
    scanned_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    detector    TEXT,
    name        TEXT,
    description TEXT,
    severity    TEXT,
    score       INTEGER,
    evidence    TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_md5    ON scans(md5);
CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_time   ON scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def _default_db_path() -> Path:
    """Возвращает путь к БД по умолчанию."""
    override = os.environ.get("RECON_DB_PATH")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".recon" / "history.db"


# ---------- Сериализация AnalysisResult ↔ dict ----------
#
# Для сохранения в БД конвертируем dataclasses в dict, в т.ч. вложенные
# (Section, Import). Используем asdict из dataclasses.

def _analysis_to_dict(analysis) -> dict:
    """AnalysisResult → dict для сериализации в JSON."""
    return {
        "schema_version": analysis.schema_version,
        "format": analysis.format,
        "filepath": analysis.filepath,
        "size": analysis.size,
        "md5": analysis.md5,
        "sha256": analysis.sha256,
        "entropy": analysis.entropy,
        "arch": analysis.arch,
        "bits": analysis.bits,
        "endianness": analysis.endianness,
        "file_type": analysis.file_type,
        "entry_point": analysis.entry_point,
        "image_base": analysis.image_base,
        "sections": [asdict(s) for s in analysis.sections],
        "imports": [asdict(i) for i in analysis.imports],
        "strings": list(analysis.strings),
        "string_count": analysis.string_count,
    }


def _dict_to_analysis(d: dict):
    """dict → AnalysisResult (для восстановления из БД)."""
    # Импорт здесь, чтобы не было циклической зависимости на уровне модуля.
    from recon.core.core_wrapper import AnalysisResult, Section, Import

    result = AnalysisResult(
        schema_version=d.get("schema_version", "1.0"),
        format=d["format"],
        filepath=d["filepath"],
        size=d["size"],
        md5=d["md5"],
        sha256=d["sha256"],
        entropy=d["entropy"],
        arch=d.get("arch", ""),
        bits=d.get("bits", 0),
        endianness=d.get("endianness", ""),
        file_type=d.get("file_type", ""),
        entry_point=d.get("entry_point", 0),
        image_base=d.get("image_base", 0),
        string_count=d.get("string_count", 0),
    )
    result.sections = [Section(**s) for s in d.get("sections", [])]
    result.imports = [Import(**i) for i in d.get("imports", [])]
    result.strings = list(d.get("strings", []))
    return result


def _risk_to_dict(risk) -> dict:
    """RiskAssessment → dict."""
    return {
        "score": risk.score,
        "level": risk.level.value,
        "findings": [
            {
                "detector": f.detector,
                "name": f.name,
                "description": f.description,
                "severity": f.severity.name,
                "score": f.severity.score,
                "evidence": f.evidence,
            }
            for f in risk.findings
        ],
        "detector_summaries": [
            {
                "detector": dr.detector,
                "total_score": dr.total_score,
                "findings_count": len(dr.findings),
            }
            for dr in risk.detector_results
        ],
    }


def _dict_to_risk(d: dict):
    """dict → RiskAssessment (упрощённое восстановление: detector_results
    без findings внутри, потому что они теперь висят на уровне risk напрямую)."""
    from recon.core.risk import RiskAssessment, RiskLevel
    from recon.detectors.base_detector import (
        Finding, Severity, DetectorResult,
    )

    findings = [
        Finding(
            detector=f["detector"],
            name=f["name"],
            description=f["description"],
            severity=Severity[f["severity"]],
            evidence=f.get("evidence", ""),
        )
        for f in d.get("findings", [])
    ]

    # Восстанавливаем DetectorResults как лёгкие "пустые" объекты —
    # findings уже распределены по уровню risk; для большинства задач
    # эти результаты не нужны после загрузки из БД.
    detector_results = [
        DetectorResult(detector=summary["detector"], findings=[])
        for summary in d.get("detector_summaries", [])
    ]

    return RiskAssessment(
        score=d["score"],
        level=RiskLevel(d["level"]),
        findings=findings,
        detector_results=detector_results,
    )


# ---------- Database класс ----------

class Database:
    """
    Обёртка над SQLite-хранилищем истории.

    Использование:
        db = Database()
        scan_id = db.save_scan(full_analysis)
        scans = db.list_scans(limit=50)
        full = db.load_scan(scan_id)
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or _default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,  # позволяем доступ из разных потоков
                                       # (Textual workers); защищаемся через
                                       # короткие транзакции
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        # WAL — Write-Ahead Logging. Лучшая параллельность для смешанного
        # чтения/записи, не нужна для нашего объёма, но дешева и полезна.
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ---- Save / load ----

    def save_scan(self, full_analysis) -> int:
        """
        Сохраняет FullAnalysis в БД, возвращает ID нового скана.
        """
        a = full_analysis.analysis
        r = full_analysis.risk

        raw_json  = json.dumps(_analysis_to_dict(a), ensure_ascii=False)
        risk_json = json.dumps(_risk_to_dict(r),     ensure_ascii=False)

        filename = Path(a.filepath).name

        with self._conn:
            cur = self._conn.execute(
                """
                INSERT INTO scans (
                    filepath, filename, format, arch, size,
                    md5, sha256, entropy,
                    risk_score, risk_level, findings_count,
                    raw_json, risk_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    a.filepath, filename, a.format, a.arch, a.size,
                    a.md5, a.sha256, a.entropy,
                    r.score, r.level.value, len(r.findings),
                    raw_json, risk_json,
                ),
            )
            scan_id = cur.lastrowid
            assert scan_id is not None

            # Вставляем findings отдельно для возможности SQL-запросов.
            for f in r.findings:
                self._conn.execute(
                    """
                    INSERT INTO findings (
                        scan_id, detector, name, description,
                        severity, score, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id, f.detector, f.name, f.description,
                        f.severity.name, f.severity.score, f.evidence,
                    ),
                )

        return scan_id

    def load_scan(self, scan_id: int):
        """
        Восстанавливает FullAnalysis по ID. Возвращает None если ID нет.
        """
        from recon.analyzer import FullAnalysis

        row = self._conn.execute(
            "SELECT raw_json, risk_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if row is None:
            return None

        analysis = _dict_to_analysis(json.loads(row["raw_json"]))
        risk     = _dict_to_risk(json.loads(row["risk_json"]))
        return FullAnalysis(analysis=analysis, risk=risk)

    # ---- Запросы для UI ----

    def list_scans(
        self,
        *,
        query: str = "",
        risk_levels: Optional[list[str]] = None,
        limit: int = 200,
    ) -> list[dict]:
        """
        Возвращает список сканов с фильтрацией.

        @param query        Подстрока для фильтра по имени файла / hashes.
        @param risk_levels  Список разрешённых уровней (None = все).
        @param limit        Максимум возвращаемых строк.

        @return Список dict-ов с базовыми полями скана.
        """
        sql = """
            SELECT id, filepath, filename, format, arch, size,
                   md5, sha256, entropy,
                   risk_score, risk_level, findings_count,
                   scanned_at
              FROM scans
             WHERE 1=1
        """
        params: list = []

        if query:
            sql += " AND (filename LIKE ? OR md5 LIKE ? OR sha256 LIKE ?)"
            like = f"%{query}%"
            params.extend([like, like, like])

        if risk_levels:
            placeholders = ",".join("?" * len(risk_levels))
            sql += f" AND risk_level IN ({placeholders})"
            params.extend(risk_levels)

        sql += " ORDER BY scanned_at DESC, id DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def delete_scan(self, scan_id: int) -> bool:
        """Удаляет скан и связанные findings (через FK ON DELETE CASCADE)."""
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM scans WHERE id = ?", (scan_id,)
            )
        return cur.rowcount > 0

    def total_scans(self) -> int:
        """Общее количество сохранённых сканов."""
        row = self._conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()
        return int(row["c"])

    def stats_by_level(self) -> dict[str, int]:
        """Сколько сканов какого уровня."""
        rows = self._conn.execute(
            "SELECT risk_level, COUNT(*) AS c FROM scans GROUP BY risk_level"
        ).fetchall()
        return {row["risk_level"]: int(row["c"]) for row in rows}
