"""
AnalyzeScreen — экран запуска анализа файла.

Логика:
  1. Пользователь вводит путь в Input или нажимает «Browse» (на Дне 8
     просто свободный ввод; диалоговый выбор файла — отдельная сложная тема).
  2. Нажимает Enter / кнопку «Scan».
  3. Запускается worker: фоновый поток вызывает Analyzer.analyze().
  4. Пока worker работает — UI показывает ProgressBar (indeterminate
     режим, потому что мы не знаем сколько % сделано) и блокирует
     повторный запуск.
  5. По завершении worker:
       - Успех → push'аем ResultsScreen с результатом.
       - Ошибка → показываем сообщение об ошибке.

Worker — это ключевая концепция. Без него subprocess.run() блокировал
бы основной поток Textual'а, и UI замирал на 1-2 секунды на каждом
анализе.
"""

from __future__ import annotations

import os
from pathlib import Path

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, ProgressBar, Static

from recon.analyzer import Analyzer, FullAnalysis
from recon.core.core_wrapper import CoreError


class AnalyzeScreen(Screen):
    """Экран для запуска анализа одного файла."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # Флаг, чтобы не запускать второй анализ пока первый идёт.
        self._busy = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="analyze-root"):
            yield Static(
                "[b]Analyze a binary file[/b]\n"
                "Enter the full path to an ELF or PE executable.",
                id="analyze-intro",
                markup=True,
            )

            yield Input(
                placeholder="/path/to/binary  or  C:\\path\\to\\binary.exe",
                id="path-input",
            )

            with Center():
                with Vertical(id="analyze-actions"):
                    yield Button("Scan File", id="btn-scan", variant="primary")
                    yield Button("Back", id="btn-back")

            # Прогресс-бар скрыт до начала анализа.
            with Vertical(id="progress-box", classes="hidden"):
                yield Static("[b]Analyzing...[/b]", id="progress-label", markup=True)
                yield ProgressBar(id="progress-bar", show_eta=False)

            # Сюда печатаем ошибки.
            yield Static("", id="status-line", markup=True)

        yield Footer()

    def on_mount(self) -> None:
        """Сразу ставим фокус на поле ввода."""
        self.query_one("#path-input", Input).focus()

    # ---- Обработчики событий ----

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Срабатывает по Enter в поле ввода."""
        self._start_analysis(event.value.strip())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-scan":
            path_input = self.query_one("#path-input", Input)
            self._start_analysis(path_input.value.strip())
        elif bid == "btn-back":
            self.app.pop_screen()

    # ---- Логика запуска анализа ----

    def _start_analysis(self, raw_path: str) -> None:
        """Валидирует путь и запускает worker."""
        status = self.query_one("#status-line", Static)

        if self._busy:
            status.update("[yellow]Analysis already in progress...[/yellow]")
            return

        if not raw_path:
            status.update("[red]Please enter a file path.[/red]")
            return

        # Разворачиваем ~ и переменные окружения, нормализуем путь.
        path = Path(os.path.expanduser(os.path.expandvars(raw_path))).resolve()

        if not path.is_file():
            status.update(f"[red]File not found: {path}[/red]")
            return

        if not os.access(path, os.R_OK):
            status.update(f"[red]No read permission: {path}[/red]")
            return

        # Показать прогресс, заблокировать кнопку.
        status.update("")
        self.query_one("#progress-box").remove_class("hidden")
        progress = self.query_one("#progress-bar", ProgressBar)
        progress.update(total=None)  # indeterminate mode
        self.query_one("#btn-scan", Button).disabled = True

        self._busy = True
        # Запускаем worker. Декоратор @work делает остальное.
        self._do_analysis(str(path))

    @work(thread=True, exclusive=True)
    def _do_analysis(self, filepath: str) -> None:
        """
        Worker — выполняется в отдельном потоке.

        `thread=True`     — выполнение в потоке, не в asyncio. Это важно
                            для subprocess.run, который синхронный.
        `exclusive=True`  — если запустить worker второй раз, первый
                            отменится. Нам это не нужно (мы блокируем
                            кнопку), но полезно как защита.

        Worker нельзя напрямую обновлять виджеты — это нужно делать через
        self.app.call_from_thread(), который маршалит вызов в основной
        поток Textual.
        """
        analyzer: Analyzer = self.app.analyzer  # type: ignore[attr-defined]

        try:
            result = analyzer.analyze(filepath)
            self.app.call_from_thread(self._on_analysis_complete, result)
        except (FileNotFoundError, CoreError) as e:
            self.app.call_from_thread(self._on_analysis_error, str(e))
        except Exception as e:
            # Любая непредвиденная ошибка — показываем как fallback.
            self.app.call_from_thread(
                self._on_analysis_error, f"Unexpected error: {e}"
            )

    # ---- Callbacks worker'а (всегда в основном потоке) ----

    def _on_analysis_complete(self, result: FullAnalysis) -> None:
        """Анализ завершён успешно."""
        self._reset_ui()
        # Импортируем здесь, чтобы избежать циклической зависимости
        # на уровне модулей.
        from recon.tui.screens.results import ResultsScreen
        self.app.push_screen(ResultsScreen(result))

    def _on_analysis_error(self, message: str) -> None:
        """Анализ упал."""
        self._reset_ui()
        status = self.query_one("#status-line", Static)
        status.update(f"[red]Error: {message}[/red]")

    def _reset_ui(self) -> None:
        """Возвращает UI в состояние до начала анализа."""
        self._busy = False
        self.query_one("#progress-box").add_class("hidden")
        self.query_one("#btn-scan", Button).disabled = False
