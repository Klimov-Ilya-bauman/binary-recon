"""
CLI entry point. Запускается как `recon <file>` или `python -m recon <file>`.

Поддерживает флаги:
    --json      Вывод в JSON (для скриптов и pipeline)
    -q --quiet  Краткий вывод (одна строка: путь, уровень, score)
    -h --help   Справка
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from recon import __version__
from recon.analyzer import Analyzer, FullAnalysis
from recon.core.core_wrapper import CoreError


# ANSI цвета для уровней риска. Используем напрямую, без зависимости от rich.
_COLORS = {
    "CLEAN":    "\033[32m",  # зелёный
    "LOW":      "\033[36m",  # циан
    "MEDIUM":   "\033[33m",  # жёлтый
    "HIGH":     "\033[31m",  # красный
    "CRITICAL": "\033[1;31m",  # ярко-красный жирный
}
_RESET = "\033[0m"


def _color(level: str, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS.get(level, '')}{text}{_RESET}"


def _print_human(fa: FullAnalysis, use_color: bool) -> None:
    a = fa.analysis
    r = fa.risk

    print("=== Binary Recon Analysis ===")
    print(f"File:     {a.filepath}")
    print(f"Format:   {a.format} ({a.arch}, {a.bits}-bit)")
    print(f"Size:     {a.size:,} bytes")
    print(f"MD5:      {a.md5}")
    print(f"SHA256:   {a.sha256}")
    print(f"Entropy:  {a.entropy:.4f}")
    print()
    print(f"Risk:     {_color(r.level.value, f'{r.score}/100 — {r.level.value}', use_color)}")
    print(f"Summary:  {r.summary}")
    print()

    if r.findings:
        print(f"Findings ({len(r.findings)}):")
        for f in r.findings:
            sev_color = _COLORS.get(f.severity.name, "") if use_color else ""
            reset = _RESET if use_color else ""
            print(f"  [{sev_color}{f.severity.name:<8}{reset}] "
                  f"{f.detector}: {f.description}")
            if f.evidence:
                print(f"             evidence: {f.evidence}")
    else:
        print("No findings.")


def _print_quiet(fa: FullAnalysis, use_color: bool) -> None:
    r = fa.risk
    print(f"{fa.analysis.filepath}: "
          f"{_color(r.level.value, r.level.value, use_color)} "
          f"({r.score}/100)")


def _to_dict(fa: FullAnalysis) -> dict[str, Any]:
    a = fa.analysis
    r = fa.risk
    return {
        "filepath": a.filepath,
        "format": a.format,
        "arch": a.arch,
        "bits": a.bits,
        "size": a.size,
        "md5": a.md5,
        "sha256": a.sha256,
        "entropy": round(a.entropy, 4),
        "risk_score": r.score,
        "risk_level": r.level.value,
        "findings": [
            {
                "detector": f.detector,
                "name": f.name,
                "description": f.description,
                "severity": f.severity.name,
                "score": f.severity.score,
                "evidence": f.evidence,
            }
            for f in r.findings
        ],
        "section_count": len(a.sections),
        "import_count": len(a.imports),
        "string_count": a.string_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Binary Recon — static analysis tool for ELF and PE executables",
    )
    parser.add_argument("file", help="Path to ELF or PE binary to analyze")
    parser.add_argument("--json", action="store_true",
                        help="Output result as JSON")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Brief one-line output")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    parser.add_argument("-V", "--version", action="version",
                        version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    try:
        fa = Analyzer().analyze(args.file)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except CoreError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(_to_dict(fa), indent=2))
    elif args.quiet:
        _print_quiet(fa, use_color)
    else:
        _print_human(fa, use_color)

    # Exit code зависит от уровня риска — удобно для скриптов.
    if fa.risk.level.value in ("HIGH", "CRITICAL"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
