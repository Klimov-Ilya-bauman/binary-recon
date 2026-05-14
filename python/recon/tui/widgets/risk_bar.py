"""
RiskBar — кастомный виджет визуализации Risk Score.

Отображает горизонтальную полоску с цветом, зависящим от уровня риска:
  CLEAN    → зелёный
  LOW      → циан
  MEDIUM   → жёлтый
  HIGH     → красный
  CRITICAL → ярко-красный

Полоска заполняется пропорционально score (0–100).
"""

from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static

from recon.core.risk import RiskAssessment, RiskLevel


# Цвета для каждого уровня. Используем Rich-теги, не TCSS, потому что
# цвет здесь динамический (зависит от данных, а не от состояния виджета).
_LEVEL_COLORS = {
    RiskLevel.CLEAN:    "green",
    RiskLevel.LOW:      "cyan",
    RiskLevel.MEDIUM:   "yellow",
    RiskLevel.HIGH:     "red",
    RiskLevel.CRITICAL: "bold red",
}


class RiskBar(Static):
    """
    Виджет вида:  ████████░░░░░░░░░░░░░░░░░░  18/100  LOW

    Использование:
        bar = RiskBar()
        bar.update_from_risk(risk_assessment)
    """

    # reactive-атрибут: при изменении атрибута Textual автоматически
    # вызовет watch_risk и перерисует виджет.
    risk: reactive[RiskAssessment | None] = reactive(None)

    # Ширина полоски в клетках терминала.
    BAR_WIDTH = 30

    def update_from_risk(self, risk: RiskAssessment) -> None:
        """Обновляет содержимое виджета на основе нового RiskAssessment."""
        self.risk = risk

    def watch_risk(self, risk: RiskAssessment | None) -> None:
        """Вызывается Textual'ом, когда self.risk меняется."""
        if risk is None:
            self.update("")
            return

        # Доля заполнения полоски.
        filled = int((risk.score / 100) * self.BAR_WIDTH)
        empty = self.BAR_WIDTH - filled

        color = _LEVEL_COLORS.get(risk.level, "white")
        bar = (
            f"[{color}]{'█' * filled}[/{color}]"
            f"[dim]{'░' * empty}[/dim]"
        )

        # Само текстовое представление.
        text = (
            f"{bar}  "
            f"[bold]{risk.score:>3}/100[/bold]  "
            f"[{color}]{risk.level.value}[/{color}]"
        )
        self.update(text)
