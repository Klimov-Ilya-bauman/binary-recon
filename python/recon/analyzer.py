"""
Analyzer — главная точка входа для анализа файла.

Связывает воедино:
  - CoreWrapper (получение AnalysisResult от C++ ядра)
  - Список детекторов (получение DetectorResult от каждого)
  - RiskCalculator (получение RiskAssessment)

Возвращает FullAnalysis — единый объект со всем, что узнали о файле.
"""

from __future__ import annotations

from dataclasses import dataclass

from recon.core.core_wrapper import AnalysisResult, CoreWrapper
from recon.core.risk import RiskAssessment, RiskCalculator
from recon.detectors.anti_debug import AntiDebugDetector
from recon.detectors.base_detector import BaseDetector


@dataclass
class FullAnalysis:
    """
    Полный результат анализа: данные C++ ядра + результаты детекторов
    + итоговая оценка риска.
    """
    analysis: AnalysisResult
    risk: RiskAssessment


class Analyzer:
    """
    Главный анализатор. Принимает путь к файлу — возвращает FullAnalysis.

    На День 6 подключён только AntiDebugDetector. На Дне 7 список
    расширится до 7 детекторов.
    """

    def __init__(self, detectors: list[BaseDetector] | None = None) -> None:
        self.core = CoreWrapper()
        self.detectors: list[BaseDetector] = detectors if detectors is not None else [
            AntiDebugDetector(),
        ]
        self.risk_calculator = RiskCalculator()

    def analyze(self, filepath: str) -> FullAnalysis:
        # 1. Парсинг файла через C++ ядро.
        result = self.core.analyze(filepath)

        # 2. Прогон через все зарегистрированные детекторы.
        detector_results = [d.detect(result) for d in self.detectors]

        # 3. Подсчёт итогового риска.
        risk = self.risk_calculator.calculate(detector_results)

        return FullAnalysis(analysis=result, risk=risk)
