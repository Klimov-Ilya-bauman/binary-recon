"""
Smoke tests. Проверяют, что базовый pipeline работает end-to-end и
что калибровка детекторов не уехала.

Пропускаются на CI, если C++ ядро не собрано — это нормально, основная
сборка уже проверяет компиляцию отдельным шагом.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_BIN = REPO_ROOT / "core" / "build" / "core"

# Если ядро не собрано — пропускаем все тесты в этом модуле.
pytestmark = pytest.mark.skipif(
    not CORE_BIN.is_file() or not os.access(CORE_BIN, os.X_OK),
    reason=f"C++ core not built at {CORE_BIN}",
)


@pytest.fixture(scope="module")
def analyzer():
    """Создаём один Analyzer на весь модуль — экономит время."""
    from recon.analyzer import Analyzer
    return Analyzer()


def test_bin_ls_is_clean(analyzer):
    """
    /bin/ls — системная утилита, не должна давать никаких findings.
    Если этот тест упал — кто-то перекалибровал детекторы слишком агрессивно.
    """
    result = analyzer.analyze("/bin/ls")
    assert result.risk.score == 0, (
        f"/bin/ls expected CLEAN (0), got {result.risk.score}: "
        + ", ".join(f.description for f in result.risk.findings)
    )
    assert result.risk.level.value == "CLEAN"
    assert len(result.risk.findings) == 0


def test_bin_ls_metadata_correct(analyzer):
    """Базовая проверка, что core корректно парсит ELF."""
    result = analyzer.analyze("/bin/ls")
    a = result.analysis
    assert a.format == "ELF"
    assert a.bits in (32, 64)
    assert a.arch in ("x86_64", "ARM64", "x86", "ARM", "RISC-V")
    assert len(a.md5) == 32
    assert len(a.sha256) == 64
    assert 0.0 <= a.entropy <= 8.0
    assert len(a.sections) > 0


def test_hello_exe_detects_isdebuggerpresent(analyzer):
    """
    hello.exe собран mingw с явным вызовом IsDebuggerPresent.
    AntiDebug-детектор обязан это поймать.
    Тест пропускается, если файла нет (например, mingw не установлен).
    """
    hello = REPO_ROOT / "tests" / "samples" / "windows" / "hello.exe"
    if not hello.is_file():
        pytest.skip("hello.exe not built — run mingw-w64 setup")

    result = analyzer.analyze(str(hello))
    assert result.analysis.format == "PE"

    antidebug_findings = [
        f for f in result.risk.findings
        if f.detector == "AntiDebug"
    ]
    assert antidebug_findings, "AntiDebug should have at least one finding"

    evidences = [f.evidence for f in antidebug_findings]
    assert any("IsDebuggerPresent" in e for e in evidences), (
        f"Expected IsDebuggerPresent in AntiDebug evidence, got {evidences}"
    )


def test_pe_format_detection(analyzer):
    """PE-парсер должен корректно определять класс и архитектуру."""
    hello = REPO_ROOT / "tests" / "samples" / "windows" / "hello.exe"
    if not hello.is_file():
        pytest.skip("hello.exe not built")

    a = analyzer.analyze(str(hello)).analysis
    assert a.format == "PE"
    assert a.bits == 64
    assert a.arch == "x86_64"
    assert a.image_base > 0
    # KERNEL32 должен быть среди импортов hello.exe
    dlls = {imp.dll.lower() for imp in a.imports if imp.dll}
    assert "kernel32.dll" in dlls
