"""
HistoryScreen — экран истории сохранённых анализов.

Поведение:
  - При открытии показывает последние 200 сканов, отсортированные
    по времени (новые сверху).
  - Поиск по имени файла, MD5 или SHA256.
  - Фильтр по risk level через кнопки.
  - Enter на строке — открыть ResultsScreen с тем сканом (без
    повторного запуска C++ ядра — данные восстанавливаются из БД).
  - Клавиша D — удалить выбранную запись.
"""

from __future__ import annotations

from datetime import datetime

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, Static,
)


_RISK_COLORS = {
    "CLEAN":    "green",
    "LOW":      "cyan",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red",
}

# Все уровни в порядке возрастания серьёзности.
_ALL_LEVELS = ["CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class HistoryScreen(Screen):
    """История сохранённых анализов."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back",   show=True),
        Binding("d",      "delete_row",     "Delete", show=True),
        Binding("r",      "refresh",        "Reload", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # Фильтр уровней: пустое множество = все.
        self._level_filter: set[str] = set()
        # Кэш текущих строк (id-ы), чтобы по индексу строки таблицы
        # получить scan_id.
        self._row_ids: list[int] = []

    def compose(self) -> ComposeResult:
        yield Header()

        with Vertical(id="history-root"):
            # Шапка со счётчиком.
            yield Static("", id="history-summary", markup=True)

            # Поиск + фильтры уровней.
            with Horizontal(id="history-controls"):
                yield Input(
                    placeholder="Search by filename, MD5, SHA256...",
                    id="history-search",
                )

            with Horizontal(id="history-filters"):
                for level in _ALL_LEVELS:
                    yield Button(
                        level,
                        id=f"flt-{level}",
                        variant="default",
                        classes="filter-btn",
                    )

            # Таблица сканов.
            yield DataTable(id="history-table")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Time", "File", "Format", "Arch", "Risk", "Findings")
        self._refresh_data()

    # ---- Обработчики ----

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "history-search":
            self._refresh_data()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid.startswith("flt-"):
            level = bid[4:]
            # Toggle уровня в фильтре.
            if level in self._level_filter:
                self._level_filter.remove(level)
                event.button.variant = "default"
            else:
                self._level_filter.add(level)
                event.button.variant = "primary"
            self._refresh_data()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Срабатывает по Enter на строке таблицы."""
        idx = event.cursor_row
        if 0 <= idx < len(self._row_ids):
            self._open_scan(self._row_ids[idx])

    # ---- Actions ----

    def action_refresh(self) -> None:
        self._refresh_data()

    def action_delete_row(self) -> None:
        table = self.query_one("#history-table", DataTable)
        idx = table.cursor_row
        if 0 <= idx < len(self._row_ids):
            scan_id = self._row_ids[idx]
            db = self._db()
            if db.delete_scan(scan_id):
                self._refresh_data()

    # ---- Логика ----

    def _db(self):
        """Достаёт инстанс Database из App."""
        return self.app.analyzer.database  # type: ignore[attr-defined]

    def _refresh_data(self) -> None:
        """Перечитывает данные из БД с применением фильтров."""
        search_input = self.query_one("#history-search", Input)
        query = search_input.value.strip()

        scans = self._db().list_scans(
            query=query,
            risk_levels=sorted(self._level_filter) if self._level_filter else None,
        )

        table = self.query_one("#history-table", DataTable)
        table.clear()
        self._row_ids = []

        if not scans:
            # Не оставляем таблицу пустой — добавим строку-подсказку.
            table.add_row(
                Text("—", style="dim"),
                Text("No scans found", style="dim"),
                "", "", "", "",
            )
        else:
            for scan in scans:
                ts = self._format_timestamp(scan.get("scanned_at"))
                level = scan["risk_level"]
                color = _RISK_COLORS.get(level, "white")
                risk_text = Text(
                    f"{scan['risk_score']:>3} {level}",
                    style=color,
                )
                table.add_row(
                    ts,
                    scan["filename"],
                    scan["format"],
                    scan.get("arch") or "—",
                    risk_text,
                    str(scan["findings_count"]),
                )
                self._row_ids.append(scan["id"])

        # Обновляем summary.
        total = self._db().total_scans()
        stats = self._db().stats_by_level()
        stats_str = "  ".join(
            f"[{_RISK_COLORS.get(lvl, 'white')}]{lvl}[/{_RISK_COLORS.get(lvl, 'white')}]: {stats.get(lvl, 0)}"
            for lvl in _ALL_LEVELS
        )
        self.query_one("#history-summary", Static).update(
            f"[b]Total scans:[/b] {total}    {stats_str}"
        )

    def _open_scan(self, scan_id: int) -> None:
        """Открывает ResultsScreen для выбранного скана."""
        full = self._db().load_scan(scan_id)
        if full is None:
            return
        # late-import против циклических зависимостей
        from recon.tui.screens.results import ResultsScreen
        self.app.push_screen(ResultsScreen(full))

    @staticmethod
    def _format_timestamp(value) -> str:
        """SQLite может вернуть строку или datetime — нормализуем."""
        if value is None:
            return "—"
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M")
        # Строковое представление SQLite TIMESTAMP: '2026-04-29 23:45:00'
        s = str(value)
        return s[:16]  # обрезаем секунды
