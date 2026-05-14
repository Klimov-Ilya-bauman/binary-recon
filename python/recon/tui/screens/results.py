"""
ResultsScreen — отображение результата анализа.

Структура:
  - Header
  - HeaderPanel: file, format, arch, риск
  - TabbedContent с 5 вкладками:
      * Overview  — хеши, энтропия, точка входа
      * Sections  — DataTable секций
      * Imports   — DataTable импортов
      * Findings  — таблица findings с цветовой подсветкой
      * Strings   — DataTable + Input для поиска
  - Footer

Все таблицы реализованы через DataTable, потому что он даёт:
  - Сортировку колонок (клик по заголовку)
  - Навигацию стрелками
  - Выделение строки
"""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    DataTable, Footer, Header, Input, Static, TabbedContent, TabPane,
)

from recon.analyzer import FullAnalysis
from recon.tui.widgets.findings_table import FindingsTable
from recon.tui.widgets.risk_bar import RiskBar


class ResultsScreen(Screen):
    """Экран отображения результата анализа одного файла."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back",       show=True),
        Binding("b",      "app.pop_screen", "Back",       show=False),
        Binding("o",      "show_tab('overview')", "Overview", show=False),
        Binding("s",      "show_tab('sections')", "Sections", show=False),
        Binding("i",      "show_tab('imports')",  "Imports",  show=False),
        Binding("f",      "show_tab('findings')", "Findings", show=False),
        Binding("t",      "show_tab('strings')",  "Strings",  show=False),
    ]

    def __init__(self, analysis: FullAnalysis) -> None:
        super().__init__()
        self.full = analysis

    def compose(self) -> ComposeResult:
        a = self.full.analysis
        r = self.full.risk

        yield Header()

        # ---- Шапка: имя файла, формат, риск ----
        with Vertical(id="results-header"):
            yield Static(
                f"[b]File:[/b] {a.filepath}",
                id="header-file", markup=True,
            )
            yield Static(
                f"[b]Format:[/b] {a.format}  ([cyan]{a.arch}[/cyan], "
                f"{a.bits}-bit)   "
                f"[b]Size:[/b] {a.size:,} bytes",
                id="header-meta", markup=True,
            )
            yield Static(
                f"[b]Summary:[/b] {r.summary}",
                id="header-summary", markup=True,
            )
            yield RiskBar(id="risk-bar")

        # ---- Вкладки ----
        with TabbedContent(initial="overview", id="results-tabs"):
            with TabPane("Overview", id="overview"):
                yield self._compose_overview()

            with TabPane("Sections", id="sections"):
                yield DataTable(id="sections-table")

            with TabPane("Imports", id="imports"):
                yield DataTable(id="imports-table")

            with TabPane("Findings", id="findings"):
                yield FindingsTable(id="findings-table")

            with TabPane("Strings", id="strings"):
                with Vertical(id="strings-pane"):
                    yield Input(placeholder="Filter strings...", id="string-filter")
                    yield DataTable(id="strings-table")

        yield Footer()

    def on_mount(self) -> None:
        """Заполняем все вкладки данными."""
        a = self.full.analysis
        r = self.full.risk

        # RiskBar — через reactive update.
        self.query_one("#risk-bar", RiskBar).update_from_risk(r)

        # Sections
        sections = self.query_one("#sections-table", DataTable)
        sections.cursor_type = "row"
        sections.zebra_stripes = True
        sections.add_columns("Name", "Address", "Size", "Flags", "Entropy")
        for s in a.sections:
            if not s.name:
                continue  # пропускаем NULL-секцию ELF
            sections.add_row(
                s.name,
                f"0x{s.address:x}",
                f"{s.size:,}",
                s.flags or "—",
                f"{s.entropy:.2f}",
            )

        # Imports
        imports = self.query_one("#imports-table", DataTable)
        imports.cursor_type = "row"
        imports.zebra_stripes = True
        if a.format == "PE":
            imports.add_columns("DLL", "Function")
            for imp in a.imports:
                imports.add_row(imp.dll, imp.function)
        else:
            imports.add_columns("Symbol")
            for imp in a.imports:
                imports.add_row(imp.function)

        # Findings
        findings = self.query_one("#findings-table", FindingsTable)
        findings.populate(r.findings)

        # Strings
        strings_table = self.query_one("#strings-table", DataTable)
        strings_table.cursor_type = "row"
        strings_table.zebra_stripes = True
        strings_table.add_columns("String")
        self._all_strings = list(a.strings)  # сохраняем для фильтра
        self._refresh_strings("")

    # ---- Composition helper для Overview ----

    def _compose_overview(self) -> Static:
        """Собирает текст вкладки Overview одним блоком."""
        a = self.full.analysis
        lines = [
            f"[b]MD5:[/b]       {a.md5}",
            f"[b]SHA256:[/b]    {a.sha256}",
            f"[b]Entropy:[/b]   {a.entropy:.4f}  [dim](range 0.0 – 8.0)[/dim]",
            "",
            f"[b]Entry point:[/b]    0x{a.entry_point:x}",
        ]
        if a.format == "PE":
            lines.append(f"[b]Image base:[/b]     0x{a.image_base:x}")
            lines.append(f"[b]Subsystem:[/b]      {a.file_type}")
        else:
            lines.append(f"[b]Type:[/b]           {a.file_type}")
            lines.append(f"[b]Endianness:[/b]     {a.endianness}")

        lines.extend([
            "",
            f"[b]Sections:[/b]       {len(a.sections)}",
            f"[b]Imports:[/b]        {len(a.imports)}",
            f"[b]Strings:[/b]        {a.string_count:,}",
            "",
            f"[b]Detectors run:[/b]  {len(self.full.risk.detector_results)}",
            f"[b]Findings:[/b]       {len(self.full.risk.findings)}",
        ])
        return Static("\n".join(lines), id="overview-text", markup=True)

    # ---- Поиск строк ----

    def on_input_changed(self, event: Input.Changed) -> None:
        """Срабатывает при каждом нажатии в Input строк."""
        if event.input.id == "string-filter":
            self._refresh_strings(event.value)

    def _refresh_strings(self, query: str) -> None:
        """Обновляет таблицу строк с применённым фильтром."""
        table = self.query_one("#strings-table", DataTable)
        table.clear()
        q = query.lower()
        # Ограничим количество показанных, чтобы не залить таблицу
        # на 10k строк.
        shown = 0
        max_show = 500
        for s in self._all_strings:
            if q and q not in s.lower():
                continue
            display = s if len(s) <= 200 else s[:197] + "..."
            table.add_row(Text(display))
            shown += 1
            if shown >= max_show:
                break

    # ---- Actions для переключения вкладок ----

    def action_show_tab(self, tab_id: str) -> None:
        """Переключает вкладку из биндинга (клавиши O/S/I/F/T)."""
        tabs = self.query_one("#results-tabs", TabbedContent)
        tabs.active = tab_id
