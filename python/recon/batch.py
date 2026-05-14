"""
Batch — сканирование папок.

Walk по дереву директорий, отбор файлов по магическим байтам (быстрая
проверка ELF/PE без полного анализа), параллельное сканирование через
ThreadPoolExecutor.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from recon.analyzer import Analyzer, FullAnalysis
from recon.core.core_wrapper import CoreError


@dataclass
class BatchItem:
    """Результат сканирования одного файла."""
    filepath: str
    success: bool
    analysis: Optional[FullAnalysis] = None
    error: Optional[str] = None


def is_probably_binary(path: Path) -> bool:
    """Быстрая проверка по магическим байтам — без полного открытия файла."""
    try:
        with path.open("rb") as f:
            head = f.read(4)
        if len(head) < 4:
            return False
        # ELF: 0x7F 'E' 'L' 'F'
        if head[0] == 0x7F and head[1:4] == b"ELF":
            return True
        # PE: 'M' 'Z'
        if head[:2] == b"MZ":
            return True
    except OSError:
        pass
    return False


def find_binaries(
    root: Path,
    *,
    recursive: bool = True,
    follow_symlinks: bool = False,
    max_files: int = 10_000,
) -> list[Path]:
    """
    Возвращает список бинарников ELF/PE в папке.

    Если root — symlink на директорию (типично для /bin → /usr/bin
    в Ubuntu 24+), мы его автоматически резолвим, чтобы обход
    всё равно работал.
    """
    root = root.expanduser().resolve()  # resolve уже разворачивает symlink
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    found: list[Path] = []
    walker = os.walk(root, followlinks=follow_symlinks) if recursive \
             else [(str(root), [], [p.name for p in root.iterdir() if p.is_file()])]

    for dirpath, _dirs, files in walker:
        for fname in files:
            p = Path(dirpath) / fname
            try:
                if p.is_file() and is_probably_binary(p):
                    found.append(p)
                    if len(found) >= max_files:
                        return found
            except OSError:
                continue
    return found


def run_batch(
    paths: Iterable[Path],
    *,
    analyzer: Optional[Analyzer] = None,
    workers: int = 4,
    progress_callback: Optional[Callable[[int, int, BatchItem], None]] = None,
) -> list[BatchItem]:
    """
    Параллельный анализ списка файлов.

    @param progress_callback  Вызывается после каждого файла:
                              (done, total, item).
    """
    analyzer = analyzer or Analyzer()
    paths_list = list(paths)
    total = len(paths_list)
    results: list[BatchItem] = []

    def _analyze_one(p: Path) -> BatchItem:
        try:
            fa = analyzer.analyze(str(p))
            return BatchItem(filepath=str(p), success=True, analysis=fa)
        except (FileNotFoundError, CoreError) as e:
            return BatchItem(filepath=str(p), success=False, error=str(e))
        except Exception as e:
            return BatchItem(filepath=str(p), success=False, error=f"unexpected: {e}")

    # Multiple workers безопасны: CoreWrapper использует subprocess.run,
    # каждый запуск независим. Database thread-safe (см. check_same_thread=False).
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_path = {executor.submit(_analyze_one, p): p for p in paths_list}
        for done, future in enumerate(as_completed(future_to_path), start=1):
            item = future.result()
            results.append(item)
            if progress_callback:
                progress_callback(done, total, item)

    return results
