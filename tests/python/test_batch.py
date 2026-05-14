"""Тесты batch-сканирования."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_BIN = REPO_ROOT / "core" / "build" / "core"

pytestmark = pytest.mark.skipif(
    not CORE_BIN.is_file() or not os.access(CORE_BIN, os.X_OK),
    reason="C++ core not built",
)


def test_is_probably_binary_elf():
    from recon.batch import is_probably_binary
    assert is_probably_binary(Path("/bin/ls"))


def test_is_probably_binary_text(tmp_path):
    from recon.batch import is_probably_binary
    t = tmp_path / "hello.txt"
    t.write_text("hello")
    assert not is_probably_binary(t)


def test_find_binaries_in_bin(tmp_path):
    """find_binaries finds ELF binaries in a directory we control.

    Не используем системные /bin или /usr/bin — там состав файлов
    зависит от дистрибутива и установленных пакетов, тест становится
    хрупким. Вместо этого создаём контролируемую тестовую папку
    с копиями нескольких системных бинарников.
    """
    import shutil
    from recon.batch import find_binaries

    # Копируем пару известных ELF-файлов в tmp_path.
    sources = ["/bin/ls", "/bin/cat", "/bin/echo"]
    copied: list[str] = []
    for src in sources:
        if Path(src).is_file():
            dst = tmp_path / Path(src).name
            shutil.copy2(src, dst)
            copied.append(dst.name)

    if not copied:
        pytest.skip("No system binaries available to copy")

    # Также положим простой текстовый файл — он не должен попасть.
    (tmp_path / "notes.txt").write_text("hello")

    found = find_binaries(tmp_path, recursive=False)
    names = {p.name for p in found}

    # Все скопированные ELF должны быть найдены.
    for name in copied:
        assert name in names, f"Expected to find {name}, got {names}"

    # Текстовый файл не должен быть в списке.
    assert "notes.txt" not in names


def test_run_batch_returns_results(tmp_path):
    """Прогон пары файлов через batch."""
    from recon.analyzer import Analyzer
    from recon.batch import run_batch
    from recon.core.database import Database

    db = Database(db_path=tmp_path / "batch.db")
    analyzer = Analyzer(database=db, save_to_history=True)

    results = run_batch([Path("/bin/ls"), Path("/bin/bash")],
                        analyzer=analyzer, workers=2)
    assert len(results) == 2
    successes = [r for r in results if r.success]
    assert len(successes) == 2
