"""
Exporter — преобразует FullAnalysis в JSON / Markdown / HTML отчёт.

Каждый формат имеет свою функцию export_X(full_analysis) -> str.
Возврат — готовая строка отчёта. Сохранение в файл — отдельная функция.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape


# Формат для --export флага.
ExportFormat = Literal["json", "html", "markdown", "md"]


# ============================================================================
#                                    JSON
# ============================================================================

def export_json(full_analysis, *, indent: int = 2) -> str:
    """Полный отчёт в JSON. Структура устойчивая, удобна для скриптов."""
    a = full_analysis.analysis
    r = full_analysis.risk

    data = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "file": {
            "path":    a.filepath,
            "format":  a.format,
            "arch":    a.arch,
            "bits":    a.bits,
            "size":    a.size,
            "md5":     a.md5,
            "sha256":  a.sha256,
            "entropy": round(a.entropy, 4),
            "entry_point": a.entry_point,
            "image_base":  a.image_base if a.format == "PE" else None,
            "endianness":  a.endianness if a.format == "ELF" else None,
            "type":        a.file_type,
        },
        "risk": {
            "score":    r.score,
            "level":    r.level.value,
            "summary":  r.summary,
        },
        "findings": [
            {
                "detector":    f.detector,
                "name":        f.name,
                "description": f.description,
                "severity":    f.severity.name,
                "score":       f.severity.score,
                "evidence":    f.evidence,
            }
            for f in r.findings
        ],
        "sections": [
            {
                "name":    s.name,
                "address": s.address,
                "size":    s.size,
                "flags":   s.flags,
                "entropy": round(s.entropy, 4),
            }
            for s in a.sections if s.name
        ],
        "imports": [
            {"dll": i.dll, "function": i.function}
            if i.dll else {"function": i.function}
            for i in a.imports
        ],
        "strings_count": a.string_count,
    }
    return json.dumps(data, indent=indent, ensure_ascii=False)


# ============================================================================
#                                  MARKDOWN
# ============================================================================

def export_markdown(full_analysis) -> str:
    """Markdown отчёт. Удобен для README, GitHub Issues, Slack."""
    a = full_analysis.analysis
    r = full_analysis.risk

    lines: list[str] = []
    add = lines.append

    add(f"# Binary Recon Report")
    add("")
    add(f"**File:** `{a.filepath}`  ")
    add(f"**Generated:** {datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')}")
    add("")
    add("---")
    add("")

    # Risk
    add("## Risk Assessment")
    add("")
    add(f"- **Score:** {r.score} / 100")
    add(f"- **Level:** **{r.level.value}**")
    add(f"- **Findings:** {len(r.findings)}")
    add(f"- **Summary:** {r.summary}")
    add("")

    # File metadata
    add("## File Metadata")
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add(f"| Format | {a.format} |")
    add(f"| Architecture | {a.arch} |")
    add(f"| Bitness | {a.bits}-bit |")
    add(f"| Size | {a.size:,} bytes |")
    add(f"| MD5 | `{a.md5}` |")
    add(f"| SHA256 | `{a.sha256}` |")
    add(f"| Entropy | {a.entropy:.4f} |")
    add(f"| Entry point | `0x{a.entry_point:x}` |")
    if a.format == "PE":
        add(f"| Image base | `0x{a.image_base:x}` |")
        add(f"| Subsystem | {a.file_type} |")
    else:
        add(f"| Type | {a.file_type} |")
        add(f"| Endianness | {a.endianness} |")
    add("")

    # Findings
    add("## Findings")
    add("")
    if not r.findings:
        add("_No suspicious indicators detected._")
        add("")
    else:
        add("| Severity | Detector | Description | Evidence |")
        add("|---|---|---|---|")
        for f in sorted(r.findings, key=lambda x: -x.severity.score):
            ev = f.evidence.replace("|", "\\|")[:80]
            add(f"| **{f.severity.name}** | {f.detector} | {f.description} | `{ev}` |")
        add("")

    # Sections
    add("## Sections")
    add("")
    if not a.sections:
        add("_No sections._")
    else:
        add("| Name | Address | Size | Flags | Entropy |")
        add("|---|---|---|---|---|")
        for s in a.sections:
            if not s.name:
                continue
            add(f"| `{s.name}` | `0x{s.address:x}` | {s.size:,} | "
                f"`{s.flags or '—'}` | {s.entropy:.2f} |")
    add("")

    # Imports (top 50)
    add(f"## Imports ({len(a.imports)})")
    add("")
    if not a.imports:
        add("_No imports._")
    else:
        shown = a.imports[:50]
        if a.format == "PE":
            add("| DLL | Function |")
            add("|---|---|")
            for i in shown:
                add(f"| {i.dll} | `{i.function}` |")
        else:
            add("| Symbol |")
            add("|---|")
            for i in shown:
                add(f"| `{i.function}` |")
        if len(a.imports) > 50:
            add(f"\n_... and {len(a.imports) - 50} more._")
    add("")

    add(f"## Strings")
    add("")
    add(f"_{a.string_count:,} ASCII strings (length ≥ 4) extracted._")
    add("")

    return "\n".join(lines)


# ============================================================================
#                                    HTML
# ============================================================================

# Jinja2 environment с автоэкранированием для безопасности.
_TEMPLATE_DIR = Path(__file__).parent / "templates"
_jinja = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def export_html(full_analysis) -> str:
    """HTML отчёт с inline CSS. Самодостаточный — никаких внешних ресурсов."""
    a = full_analysis.analysis
    r = full_analysis.risk

    template = _jinja.get_template("report.html.j2")
    return template.render(
        analysis=a,
        risk=r,
        findings_sorted=sorted(r.findings, key=lambda x: -x.severity.score),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        sections_visible=[s for s in a.sections if s.name],
        imports_visible=a.imports[:200],
        imports_remaining=max(0, len(a.imports) - 200),
    )


# ============================================================================
#                              ROUTING / FILE SAVE
# ============================================================================

def export_to_string(full_analysis, fmt: ExportFormat) -> str:
    """Маршрутизация по формату."""
    fmt = fmt.lower()  # type: ignore
    if fmt == "json":
        return export_json(full_analysis)
    if fmt in ("md", "markdown"):
        return export_markdown(full_analysis)
    if fmt == "html":
        return export_html(full_analysis)
    raise ValueError(f"Unknown export format: {fmt}")


def export_to_file(full_analysis, fmt: ExportFormat, output_path: str) -> Path:
    """Сохраняет отчёт в файл. Возвращает финальный путь."""
    content = export_to_string(full_analysis, fmt)
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
