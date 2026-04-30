"""
RiskCalculator — превращает список findings от детекторов в итоговый
числовой score и текстовый уровень риска.

Логика проста: каждый Finding имеет Severity со своим весом в баллах.
Итоговый score = сумма весов всех findings, ограниченная 100. Уровень
определяется по порогам.

Уровни риска:
    CLEAN    : 0       — никаких подозрительных индикаторов
    LOW      : 1-19    — мелкие индикаторы, чаще всего false positive
    MEDIUM   : 20-39   — несколько индикаторов, заслуживает внимания
    HIGH     : 40-69   — комбинация серьёзных индикаторов
    CRITICAL : 70-100  — почти наверняка вредонос
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from recon.detectors.base_detector import DetectorResult, Finding


class RiskLevel(str, Enum):
    """Классификация итогового риска. Наследуется от str чтобы напрямую
    сериализоваться в JSON."""
    CLEAN    = "CLEAN"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# Пороги для маппинга score → level.
# Если score >= порога — присваиваем уровень.
_THRESHOLDS = (
    (70, RiskLevel.CRITICAL),
    (40, RiskLevel.HIGH),
    (20, RiskLevel.MEDIUM),
    (1,  RiskLevel.LOW),
    (0,  RiskLevel.CLEAN),
)


@dataclass
class RiskAssessment:
    """Итоговая оценка риска бинарника."""
    score: int                          # 0..100
    level: RiskLevel
    findings: list[Finding] = field(default_factory=list)
    detector_results: list[DetectorResult] = field(default_factory=list)

    @property
    def summary(self) -> str:
        """Короткое описание для вывода."""
        if self.level == RiskLevel.CLEAN:
            return "No suspicious indicators detected"
        n = len(self.findings)
        return f"{n} finding{'s' if n != 1 else ''} across {len(self.detector_results)} detectors"


class RiskCalculator:
    """
    Принимает список DetectorResult'ов и возвращает RiskAssessment.

    Score не может превысить 100 — это сознательный потолок: бинарник
    с риском 100 либо с риском 250 одинаково плох, нет смысла увеличивать.
    """

    MAX_SCORE = 100

    def calculate(self, detector_results: list[DetectorResult]) -> RiskAssessment:
        all_findings: list[Finding] = []
        raw_score = 0

        for dr in detector_results:
            all_findings.extend(dr.findings)
            for f in dr.findings:
                raw_score += f.severity.score

        score = min(raw_score, self.MAX_SCORE)
        level = self._level_for_score(score)

        return RiskAssessment(
            score=score,
            level=level,
            findings=all_findings,
            detector_results=list(detector_results),
        )

    @staticmethod
    def _level_for_score(score: int) -> RiskLevel:
        for threshold, level in _THRESHOLDS:
            if score >= threshold:
                return level
        return RiskLevel.CLEAN
