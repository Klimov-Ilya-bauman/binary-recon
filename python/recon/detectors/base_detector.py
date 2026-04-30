"""
BaseDetector — абстрактный класс, шаблон всех детекторов проекта.

Каждый детектор реализует один аспект анализа: AntiDebug, Network,
Packer и т.д. Детектор получает на вход AnalysisResult (что C++ ядро
извлекло из файла) и возвращает DetectorResult — список Finding'ов.

Severity-веса подобраны эмпирически:
    LOW      = 3  — мелкий индикатор (например, упоминание соц.сети в строках)
    MEDIUM   = 8  — заметный индикатор (например, импорт socket)
    HIGH     = 15 — серьёзный индикатор (CreateRemoteThread, ptrace)
    CRITICAL = 25 — почти однозначный признак вредоноса
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum

from recon.core.core_wrapper import AnalysisResult


class Severity(IntEnum):
    """Уровень серьёзности находки. Значение = баллы в общем счёте риска."""
    LOW      = 3
    MEDIUM   = 8
    HIGH     = 15
    CRITICAL = 25

    @property
    def score(self) -> int:
        """Псевдоним для значения, чтобы код в RiskCalculator читался лучше."""
        return int(self)


@dataclass
class Finding:
    """
    Одна находка детектора. Объясняет, что именно было обнаружено и
    почему это считается подозрительным.
    """
    detector: str          # имя детектора-источника, например "AntiDebug"
    name: str              # короткое имя находки, например "ptrace_import"
    description: str       # человекочитаемое описание
    severity: Severity
    evidence: str = ""     # конкретное доказательство (имя функции, строка)


@dataclass
class DetectorResult:
    """Результат работы одного детектора."""
    detector: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_score(self) -> int:
        return sum(f.severity.score for f in self.findings)

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0


class BaseDetector(ABC):
    """
    Базовый класс детектора. Подкласс должен:
      1. Задать атрибут NAME (используется в Finding.detector).
      2. Реализовать метод detect(analysis) → DetectorResult.
    """

    NAME: str = "BaseDetector"

    @abstractmethod
    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        """Анализирует AnalysisResult и возвращает DetectorResult."""
        raise NotImplementedError

    # ----- Утилиты, общие для большинства детекторов -----

    @staticmethod
    def has_import(analysis: AnalysisResult, function_name: str) -> bool:
        """
        Проверяет, есть ли в импортах функция с указанным именем.
        Регистронезависимое сравнение, потому что Windows API
        регистронезависим (IsDebuggerPresent vs isdebuggerpresent).
        """
        target = function_name.lower()
        return any(imp.function.lower() == target for imp in analysis.imports)

    @staticmethod
    def find_imports_matching(analysis: AnalysisResult, names: list[str]) -> list[str]:
        """
        Возвращает список имён функций из `names`, которые присутствуют
        в импортах файла. Регистронезависимое сравнение.
        """
        wanted = {n.lower() for n in names}
        return sorted({
            imp.function for imp in analysis.imports
            if imp.function.lower() in wanted
        })

    @staticmethod
    def find_strings_matching(analysis: AnalysisResult, substrings: list[str]) -> list[str]:
        """
        Ищет строки, содержащие любой из подстрок (регистронезависимо).
        """
        wanted = [s.lower() for s in substrings]
        result: list[str] = []
        for s in analysis.strings:
            s_lower = s.lower()
            if any(w in s_lower for w in wanted):
                result.append(s)
        return result
