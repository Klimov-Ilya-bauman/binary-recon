"""ExportModalScreen — модальный выбор формата экспорта."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from recon.analyzer import FullAnalysis
from recon.export.exporter import export_to_file


class ExportModalScreen(ModalScreen):
    """Модальное окно выбора формата и пути экспорта."""

    BINDINGS = [Binding("escape", "app.pop_screen", "Cancel", show=True)]

    def __init__(self, analysis: FullAnalysis) -> None:
        super().__init__()
        self.full = analysis

    def compose(self) -> ComposeResult:
        with Vertical(id="export-modal"):
            yield Static("[b]Export report[/b]", markup=True)
            yield Static("Format:")
            with Center():
                with Vertical(id="export-buttons"):
                    yield Button("JSON",     id="exp-json",     variant="primary")
                    yield Button("HTML",     id="exp-html",     variant="primary")
                    yield Button("Markdown", id="exp-markdown", variant="primary")
                    yield Button("Cancel",   id="exp-cancel")
            yield Static("Output path (optional):")
            yield Input(placeholder="report.html", id="exp-path")
            yield Static("", id="exp-status", markup=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "exp-cancel":
            self.app.pop_screen()
            return
        if not bid.startswith("exp-"):
            return
        fmt = bid[4:]
        if fmt not in ("json", "html", "markdown"):
            return

        path_input = self.query_one("#exp-path", Input).value.strip()
        ext = "md" if fmt == "markdown" else fmt
        out_path = path_input or f"report.{ext}"

        status = self.query_one("#exp-status", Static)
        try:
            saved = export_to_file(self.full, fmt, out_path)
            status.update(f"[green]✓ Saved to {saved}[/green]")
        except Exception as e:
            status.update(f"[red]Error: {e}[/red]")
