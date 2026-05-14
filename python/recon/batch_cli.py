"""CLI entry point для batch-сканирования: `recon-batch <dir>`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from recon import __version__
from recon.batch import find_binaries, run_batch


_COLORS = {
    "CLEAN":    "\033[32m",
    "LOW":      "\033[36m",
    "MEDIUM":   "\033[33m",
    "HIGH":     "\033[31m",
    "CRITICAL": "\033[1;31m",
}
_RESET = "\033[0m"


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="recon-batch",
        description="Batch scan a directory for suspicious ELF/PE binaries",
    )
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("--no-recursive", action="store_true",
                        help="Don't descend into subdirectories")
    parser.add_argument("-w", "--workers", type=int, default=4,
                        help="Parallel workers (default: 4)")
    parser.add_argument("--max-files", type=int, default=10000,
                        help="Maximum files to scan (default: 10000)")
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    try:
        binaries = find_binaries(
            Path(args.directory),
            recursive=not args.no_recursive,
            max_files=args.max_files,
        )
    except NotADirectoryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if not binaries:
        print(f"No ELF/PE binaries found in {args.directory}")
        return 0

    print(f"Scanning {len(binaries)} binaries with {args.workers} workers...\n",
          file=sys.stderr)

    use_color = sys.stdout.isatty()

    def on_progress(done: int, total: int, item) -> None:
        if not item.success:
            print(f"[{done}/{total}] ERROR  {item.filepath}: {item.error}",
                  file=sys.stderr)
            return
        r = item.analysis.risk
        col = _COLORS.get(r.level.value, "") if use_color else ""
        reset = _RESET if use_color else ""
        print(f"[{done}/{total}] {col}{r.level.value:<8}{reset} "
              f"{r.score:>3}/100  {item.filepath}",
              file=sys.stderr)

    results = run_batch(binaries, workers=args.workers, progress_callback=on_progress)

    # Финальная сводка
    print("\n=== Summary ===", file=sys.stderr)
    by_level: dict[str, int] = {}
    failed = 0
    for item in results:
        if not item.success:
            failed += 1
            continue
        lvl = item.analysis.risk.level.value
        by_level[lvl] = by_level.get(lvl, 0) + 1

    for level in ("CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        count = by_level.get(level, 0)
        if count == 0:
            continue
        col = _COLORS.get(level, "") if use_color else ""
        reset = _RESET if use_color else ""
        print(f"  {col}{level:<8}{reset}  {count}", file=sys.stderr)
    if failed:
        print(f"  ERRORS    {failed}", file=sys.stderr)

    # Exit code: 1 если есть HIGH/CRITICAL
    if by_level.get("HIGH", 0) or by_level.get("CRITICAL", 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
