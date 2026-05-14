"""BatchScreen — TUI экран batch-сканирования."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import (
    Button, DataTable, Footer, Header, Input, ProgressBar, Static,
)


_RISK_COLORS = {
    "CLEAN":    "green",
    "LOW":      "cyan",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red",
}


class BatchScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back", show=True)]

    def __init__(self) -> None:
        super().__init__()
        self._busy = False
        self._scan_ids: list[int] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="batch-root"):
            yield Static("[b]Batch scan a directory[/b]", markup=True)
            yield Input(placeholder="/path/to/directory", id="batch-path")
            yield Button("Start scan", id="batch-start", variant="primary")
            yield ProgressBar(id="batch-progress", classes="hidden")
            yield Static("", id="batch-status", markup=True)
            yield DataTable(id="batch-table")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#batch-path", Input).focus()
        table = self.query_one("#batch-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("File", "Format", "Risk", "Findings")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "batch-start":
            self._start()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._scan_ids):
            scan_id = self._scan_ids[idx]
            if scan_id < 0:
                return
            db = self.app.analyzer.database  # type: ignore[attr-defined]
            full = db.load_scan(scan_id)
            if full:
                from recon.tui.screens.results import ResultsScreen
                self.app.push_screen(ResultsScreen(full))

    def _start(self) -> None:
        path_input = self.query_one("#batch-path", Input).value.strip()
        status = self.query_one("#batch-status", Static)
        if self._busy:
            status.update("[yellow]Already scanning...[/yellow]")
            return
        if not path_input:
            status.update("[red]Enter a directory path.[/red]")
            return
        target = Path(path_input).expanduser()
        if not target.is_dir():
            status.update(f"[red]Not a directory: {target}[/red]")
            return

        self.query_one("#batch-table", DataTable).clear()
        self._scan_ids = []
        progress = self.query_one("#batch-progress", ProgressBar)
        progress.remove_class("hidden")
        progress.update(total=None, progress=0)
        self.query_one("#batch-start", Button).disabled = True
        self._busy = True
        status.update("[dim]Discovering binaries...[/dim]")
        self._run_batch(str(target))

    @work(thread=True, exclusive=True)
    def _run_batch(self, directory: str) -> None:
        from recon.batch import find_binaries, run_batch

        try:
            binaries = find_binaries(Path(directory), recursive=True)
        except Exception as e:
            self.app.call_from_thread(self._on_error, str(e))
            return

        total = len(binaries)
        self.app.call_from_thread(self._on_discovered, total)

        if total == 0:
            self.app.call_from_thread(self._on_complete, 0)
            return

        analyzer = self.app.analyzer  # type: ignore[attr-defined]

        def on_progress(done, total_, item):
            self.app.call_from_thread(self._on_item, done, total_, item)

        run_batch(binaries, analyzer=analyzer, workers=4,
                  progress_callback=on_progress)
        self.app.call_from_thread(self._on_complete, total)

    # ---- Callbacks main thread ----

    def _on_discovered(self, total: int) -> None:
        status = self.query_one("#batch-status", Static)
        status.update(f"[b]Found {total} binaries[/b]")
        progress = self.query_one("#batch-progress", ProgressBar)
        progress.update(total=total, progress=0)

    def _on_item(self, done: int, total: int, item) -> None:
        progress = self.query_one("#batch-progress", ProgressBar)
        progress.update(progress=done)

        table = self.query_one("#batch-table", DataTable)
        if not item.success:
            table.add_row(item.filepath, "—",
                          Text("ERROR", style="red"), item.error or "")
            self._scan_ids.append(-1)
            return
        a = item.analysis.analysis
        r = item.analysis.risk
        col = _RISK_COLORS.get(r.level.value, "white")
        risk_text = Text(f"{r.score:>3} {r.level.value}", style=col)
        table.add_row(item.filepath, a.format, risk_text, str(len(r.findings)))
        self._scan_ids.append(item.analysis.scan_id or -1)

    def _on_error(self, message: str) -> None:
        self._reset_ui()
        self.query_one("#batch-status", Static).update(f"[red]Error: {message}[/red]")

    def _on_complete(self, total: int) -> None:
        self._reset_ui()
        self.query_one("#batch-status", Static).update(
            f"[green]✓ Scanned {total} binaries[/green]"
        )

    def _reset_ui(self) -> None:
        self._busy = False
        self.query_one("#batch-start", Button).disabled = False
        self.query_one("#batch-progress", ProgressBar).add_class("hidden")
