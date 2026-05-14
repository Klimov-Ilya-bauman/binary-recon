"""
FindingsTable — DataTable, показывающий findings с цветовой
индикацией severity.

Каждая строка содержит: severity, detector, description, evidence.
Severity рендерится цветом, чтобы CRITICAL/HIGH сразу бросались в глаза.
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import DataTable

from recon.detectors.base_detector import Finding, Severity


_SEVERITY_COLORS = {
    Severity.LOW:      "cyan",
    Severity.MEDIUM:   "yellow",
    Severity.HIGH:     "red",
    Severity.CRITICAL: "bold red",
}


class FindingsTable(DataTable):
    """DataTable, преднастроенный под отображение Finding-объектов."""

    def on_mount(self) -> None:
        """Вызывается при добавлении виджета в дерево. Настраиваем колонки."""
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_columns("Severity", "Detector", "Description", "Evidence")

    def populate(self, findings: list[Finding]) -> None:
        """Заполняет таблицу списком findings."""
        self.clear()
        if not findings:
            self.add_row(
                Text("—", style="dim"),
                Text("No findings", style="green"),
                Text("This file appears clean.", style="dim"),
                Text("", style="dim"),
            )
            return

        # Сортировка по severity убыванию — самое важное сверху.
        for f in sorted(findings, key=lambda x: -x.severity.score):
            color = _SEVERITY_COLORS.get(f.severity, "white")
            sev_text = Text(f.severity.name, style=color)
            det_text = Text(f.detector, style="bold")
            desc_text = Text(f.description)
            # Evidence обрежем, если слишком длинная.
            ev = f.evidence
            if len(ev) > 60:
                ev = ev[:57] + "..."
            ev_text = Text(ev, style="dim")

            self.add_row(sev_text, det_text, desc_text, ev_text)
