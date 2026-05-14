"""Тесты Exporter — JSON, Markdown, HTML."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_BIN = REPO_ROOT / "core" / "build" / "core"

pytestmark = pytest.mark.skipif(
    not CORE_BIN.is_file() or not os.access(CORE_BIN, os.X_OK),
    reason="C++ core not built",
)


@pytest.fixture(scope="module")
def full_analysis():
    from recon.analyzer import Analyzer
    return Analyzer(save_to_history=False).analyze("/bin/ls")


def test_export_json_is_valid(full_analysis):
    from recon.export.exporter import export_json
    s = export_json(full_analysis)
    data = json.loads(s)
    assert data["file"]["format"] == "ELF"
    assert data["risk"]["level"] == "CLEAN"
    assert "md5" in data["file"]
    assert "sha256" in data["file"]


def test_export_markdown_contains_key_sections(full_analysis):
    from recon.export.exporter import export_markdown
    md = export_markdown(full_analysis)
    assert "# Binary Recon Report" in md
    assert "## Risk Assessment" in md
    assert "## File Metadata" in md
    assert "## Findings" in md
    assert full_analysis.analysis.md5 in md


def test_export_html_renders(full_analysis):
    from recon.export.exporter import export_html
    h = export_html(full_analysis)
    assert "<!DOCTYPE html>" in h
    assert "Binary Recon Report" in h
    assert full_analysis.analysis.md5 in h
    assert "risk-CLEAN" in h


def test_export_to_file_creates_file(tmp_path, full_analysis):
    from recon.export.exporter import export_to_file
    out = tmp_path / "report.html"
    saved = export_to_file(full_analysis, "html", str(out))
    assert saved.is_file()
    assert saved.read_text().startswith("<!DOCTYPE html>")


def test_export_unknown_format_raises(full_analysis):
    from recon.export.exporter import export_to_string
    with pytest.raises(ValueError):
        export_to_string(full_analysis, "xml")  # type: ignore
