"""
Analyzer — главная точка входа для анализа файла.

На День 7 подключены все 7 детекторов проекта:
    AntiDebug, Network, Packer, Persistence, Injection, Crypto, Signatures.

Detectors запускаются последовательно. Это ОК для текущего объёма работы
(каждый детектор — это десятки списочных операций), но в будущем можно
распараллелить через concurrent.futures, если потребуется.
"""

from __future__ import annotations

from dataclasses import dataclass

from recon.core.core_wrapper import AnalysisResult, CoreWrapper
from recon.core.risk import RiskAssessment, RiskCalculator
from recon.detectors.anti_debug import AntiDebugDetector
from recon.detectors.base_detector import BaseDetector
from recon.detectors.crypto import CryptoDetector
from recon.detectors.injection import InjectionDetector
from recon.detectors.network import NetworkDetector
from recon.detectors.packer import PackerDetector
from recon.detectors.persistence import PersistenceDetector
from recon.detectors.signatures import SignaturesDetector


@dataclass
class FullAnalysis:
    analysis: AnalysisResult
    risk: RiskAssessment


# Дефолтный набор детекторов — все 7. Порядок не влияет на результат,
# но влияет на порядок findings в выводе.
DEFAULT_DETECTORS: list[type[BaseDetector]] = [
    AntiDebugDetector,
    NetworkDetector,
    PackerDetector,
    PersistenceDetector,
    InjectionDetector,
    CryptoDetector,
    SignaturesDetector,
]


class Analyzer:
    """
    Главный анализатор. Принимает путь к файлу — возвращает FullAnalysis.
    По умолчанию использует все 7 детекторов; можно передать свой список.
    """

    def __init__(self, detectors: list[BaseDetector] | None = None) -> None:
        self.core = CoreWrapper()
        self.detectors: list[BaseDetector] = (
            detectors if detectors is not None
            else [cls() for cls in DEFAULT_DETECTORS]
        )
        self.risk_calculator = RiskCalculator()

    def analyze(self, filepath: str) -> FullAnalysis:
        result = self.core.analyze(filepath)
        detector_results = [d.detect(result) for d in self.detectors]
        risk = self.risk_calculator.calculate(detector_results)
        return FullAnalysis(analysis=result, risk=risk)
