"""
Analyzer — главная точка входа для анализа файла.

Подключены все 7 детекторов. После анализа результат автоматически
сохраняется в SQLite-историю (если save_to_history=True, что является
поведением по умолчанию).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from recon.core.core_wrapper import AnalysisResult, CoreWrapper
from recon.core.database import Database
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
    scan_id: Optional[int] = None     # ID в БД (None если не сохранено)


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
    Главный анализатор.

    @param detectors          Свой список детекторов (default: все 7).
    @param database           Свой инстанс Database (default: создаём новый).
    @param save_to_history    Автосохранение в БД (default: True).
    """

    def __init__(
        self,
        detectors: list[BaseDetector] | None = None,
        database: Database | None = None,
        save_to_history: bool = True,
    ) -> None:
        self.core = CoreWrapper()
        self.detectors: list[BaseDetector] = (
            detectors if detectors is not None
            else [cls() for cls in DEFAULT_DETECTORS]
        )
        self.risk_calculator = RiskCalculator()
        self.save_to_history = save_to_history
        # Database создаётся лениво при первом обращении, чтобы тесты
        # без save_to_history не трогали файловую систему.
        self._db_instance: Database | None = database

    @property
    def database(self) -> Database:
        """Lazy-init Database при первом обращении."""
        if self._db_instance is None:
            self._db_instance = Database()
        return self._db_instance

    def analyze(self, filepath: str) -> FullAnalysis:
        result = self.core.analyze(filepath)
        detector_results = [d.detect(result) for d in self.detectors]
        risk = self.risk_calculator.calculate(detector_results)

        full = FullAnalysis(analysis=result, risk=risk)

        if self.save_to_history:
            try:
                full.scan_id = self.database.save_scan(full)
            except Exception:
                # Не позволяем сбою БД ломать анализ.
                # На проде можно залогировать; для учебного — молчим.
                full.scan_id = None

        return full
