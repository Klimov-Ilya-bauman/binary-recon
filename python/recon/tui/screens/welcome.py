"""
WelcomeScreen — стартовый экран Binary Recon.

Что на нём:
  - ASCII-логотип в верхней половине
  - Меню из 5 кнопок: Analyze File, Batch Scan, History, Help, Quit
  - Footer с подсказками горячих клавиш

Что делают кнопки:
  - Analyze File: на День 8 показывает заглушку. На День 9 → AnalyzeScreen.
  - Batch Scan:   на День 8 заглушка. На День 12 → BatchScreen.
  - History:      на День 8 заглушка. На День 10 → HistoryScreen.
  - Help:         сразу работает, показывает HelpScreen.
  - Quit:         выход через app.exit().
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static


# ASCII-логотип. Использовать строки в тройных кавычках — Textual
# умеет рендерить многострочный текст в Static.
_LOGO = r"""
██████╗ ██╗███╗   ██╗ █████╗ ██████╗ ██╗   ██╗
██╔══██╗██║████╗  ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
██████╔╝██║██╔██╗ ██║███████║██████╔╝ ╚████╔╝
██╔══██╗██║██║╚██╗██║██╔══██║██╔══██╗  ╚██╔╝
██████╔╝██║██║ ╚████║██║  ██║██║  ██║   ██║
╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""

_TAGLINE = "Static analysis for ELF and PE executables"


class WelcomeScreen(Screen):
    """Стартовый экран приложения."""

    # Биндинги уровня экрана. Дополняют глобальные из ReconApp.
    BINDINGS = [
        Binding("a", "analyze", "Analyze",  show=True),
        Binding("b", "batch",   "Batch",    show=True),
        Binding("h", "history", "History",  show=True),
    ]

    def compose(self) -> ComposeResult:
        """
        Возвращает дерево виджетов экрана.
        Textual использует это для построения UI.
        """
        yield Header(show_clock=True)

        with Vertical(id="welcome-root"):
            # Логотип, центрированный.
            yield Static(_LOGO, id="logo", classes="logo")
            yield Static(_TAGLINE, id="tagline", classes="tagline")

            # Меню — 5 кнопок в столбик, центрированных.
            with Center():
                with Vertical(id="menu"):
                    yield Button("Analyze File [A]", id="btn-analyze", variant="primary")
                    yield Button("Batch Scan   [B]", id="btn-batch",   variant="default")
                    yield Button("History      [H]", id="btn-history", variant="default")
                    yield Button("Help         [?]", id="btn-help",    variant="default")
                    yield Button("Quit       [^Q]",  id="btn-quit",    variant="error")

        yield Footer()

    # ---- Обработчики кнопок ----
    #
    # Textual вызывает on_button_pressed для каждого нажатия. Чтобы
    # различить кнопки, смотрим на event.button.id.
    #
    # Альтернатива: создать декоратор @on(Button.Pressed, "#btn-analyze")
    # для каждой кнопки. Это чище, но многословнее. Для 5 кнопок —
    # один обработчик с if'ами достаточен.

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-analyze":
            self.action_analyze()
        elif bid == "btn-batch":
            self.action_batch()
        elif bid == "btn-history":
            self.action_history()
        elif bid == "btn-help":
            self.app.action_show_help()
        elif bid == "btn-quit":
            self.app.exit()

    # ---- Actions для биндингов ----

    def action_analyze(self) -> None:
        """Открыть экран анализа файла."""
        # late-import предотвращает циклическую зависимость на уровне модулей
        from recon.tui.screens.analyze import AnalyzeScreen
        self.app.push_screen(AnalyzeScreen())

    def action_batch(self) -> None:
        """Открыть экран batch-сканирования. На День 8 — заглушка."""
        self.app.push_screen(_NotImplementedScreen(
            "Batch Scan",
            "Batch scanning will be implemented in Day 12."
        ))

    def action_history(self) -> None:
        """Открыть экран истории. На День 8 — заглушка."""
        self.app.push_screen(_NotImplementedScreen(
            "History",
            "Scan history (SQLite) will be implemented in Day 10."
        ))


# =============================================================================
#                        ВСПОМОГАТЕЛЬНЫЙ "TODO" ЭКРАН
# =============================================================================

class _NotImplementedScreen(Screen):
    """
    Простой экран-заглушка для функций, которые ещё не написаны.
    Будет заменён настоящими экранами на Днях 9, 10, 12.
    """

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
    ]

    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self._title = title
        self._message = message

    def compose(self) -> ComposeResult:
        yield Header()
        with Center():
            with Vertical(id="todo-box"):
                yield Static(f"⏳  {self._title}",  classes="todo-title")
                yield Static(self._message,        classes="todo-message")
                yield Static("",                    classes="todo-spacer")
                yield Static("Press Esc to go back.", classes="todo-hint")
        yield Footer()
