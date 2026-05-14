"""
ReconApp — корневой класс TUI-приложения Binary Recon.

Это App в терминах Textual: точка входа, владелец Analyzer'а,
регистратор экранов и глобальных биндингов.

Запускается через `recon-tui` (entry point в pyproject.toml) либо
напрямую через `python -m recon.tui.app`.
"""

from __future__ import annotations

from pathlib import Path

from textual.app import App
from textual.binding import Binding

from recon.analyzer import Analyzer
from recon.tui.screens.help import HelpScreen
from recon.tui.screens.welcome import WelcomeScreen


class ReconApp(App):
    """
    Главный App. Все экраны живут внутри него.

    SCREENS — словарь "имя → класс экрана". Позволяет переключаться
    через self.push_screen("name") без явного импорта в каждом месте.

    BINDINGS — глобальные горячие клавиши, доступные везде в приложении.
    На уровне отдельного Screen могут быть свои дополнительные.
    """

    # Путь к файлу стилей TCSS. Textual подхватит автоматически.
    # Путь относительно этого .py файла.
    CSS_PATH = "app.tcss"

    TITLE = "Binary Recon"
    SUB_TITLE = "Static binary analysis · v1.0"

    # Глобальные биндинги — работают на любом экране.
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+c", "quit", "Quit", show=False),  # дублёр, но не показываем в Footer
        Binding("question_mark", "show_help", "Help", show=True),
        Binding("f1", "show_help", "Help", show=False),
    ]

    # Регистрация именованных экранов.
    SCREENS = {
        "help": HelpScreen,
    }

    def __init__(self) -> None:
        super().__init__()
        # Analyzer создаётся один раз и переиспользуется. Он лёгкий
        # (внутри только CoreWrapper и список детекторов), но создание
        # каждый раз тратит время и проверяет наличие core-бинарника.
        # Делаем один раз на старте.
        self.analyzer = Analyzer()

    def on_mount(self) -> None:
        """
        Вызывается, когда App смонтирован. Самое раннее место,
        где можно push'ить начальный экран.
        """
        self.push_screen(WelcomeScreen())

    # ---- Глобальные actions ----

    def action_show_help(self) -> None:
        """Показать экран справки. Используется биндингом ? или F1."""
        # is_screen_installed проверяет, не открыт ли уже help —
        # чтобы не пушить дубликаты при многократном нажатии.
        if not any(isinstance(s, HelpScreen) for s in self.screen_stack):
            self.push_screen(HelpScreen())


def main() -> int:
    """Entry point для команды `recon-tui` (см. pyproject.toml)."""
    app = ReconApp()
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
