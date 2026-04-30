"""
PackerDetector — обнаруживает упаковщики и обфускаторы.

Упаковщик (packer) — программа, которая берёт исходный исполняемый файл,
сжимает или шифрует его содержимое, и оборачивает в маленький загрузчик
(stub). При запуске stub распаковывает оригинальный код в память и передаёт
ему управление. Зачем:
  - Уменьшение размера (исторически — главная причина, например UPX).
  - Защита от реверс-инжиниринга (Themida, VMProtect).
  - Сокрытие вредоносного кода от антивирусов (главная причина для малвари).

Признаки упакованного бинарника:
  1. Высокая энтропия секций кода (>7.0). Сжатые/шифрованные данные
     статистически неотличимы от случайного шума.
  2. Малое количество импортов. Упакованный код подгружает функции
     динамически через GetProcAddress/LoadLibrary, поэтому в Import Table
     остаются только эти две функции и пара служебных.
  3. Нестандартные имена секций: ".upx0", ".themida", ".vmp0", ".aspack".
  4. Сигнатуры упаковщиков в строках: "UPX!", "$Info: This file is...".

Один признак сам по себе ничего не значит — натуральное шифрование (TLS,
архивы внутри ресурсов) тоже даёт высокую энтропию. Поэтому Severity
зависит от комбинации признаков.
"""

from __future__ import annotations

from recon.core.core_wrapper import AnalysisResult
from recon.detectors.base_detector import (
    BaseDetector, DetectorResult, Finding, Severity,
)


# Известные сигнатуры упаковщиков в строках бинарника.
_PACKER_SIGNATURES = (
    ("UPX!",      "UPX"),
    ("$Info: This file is packed", "UPX"),
    ("Themida",   "Themida"),
    ("VMProtect", "VMProtect"),
    ("ASPack",    "ASPack"),
    ("MPRESS",    "MPRESS"),
    ("PECompact", "PECompact"),
    ("Petite",    "Petite"),
    ("kkrunchy",  "kkrunchy"),
)

# Подозрительные имена секций — характерные для упаковщиков.
_PACKER_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2",
    ".themida", ".vmp0", ".vmp1", ".vmp2",
    ".aspack", ".adata",
    ".pec1", ".pec2",
    ".mpress1", ".mpress2",
    ".petite",
    ".nsp0", ".nsp1", ".nsp2",
}

# Минимальная энтропия секции с кодом, при которой считаем её упакованной.
_HIGH_ENTROPY_THRESHOLD = 7.0

# При каком количестве импортов считаем "подозрительно мало".
_LOW_IMPORTS_THRESHOLD = 10

# Имена секций кода для разных форматов.
_CODE_SECTION_NAMES = {".text", ".code", "CODE"}


class PackerDetector(BaseDetector):
    NAME = "Packer"

    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        result = DetectorResult(detector=self.NAME)

        # 1. Сигнатуры в строках.
        for signature, packer_name in _PACKER_SIGNATURES:
            if any(signature in s for s in analysis.strings):
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="packer_signature",
                    description=f"{packer_name} packer signature found",
                    severity=Severity.HIGH,
                    evidence=signature,
                ))

        # 2. Подозрительные имена секций.
        suspicious_sections = [
            s.name for s in analysis.sections
            if s.name.lower() in {n.lower() for n in _PACKER_SECTION_NAMES}
        ]
        if suspicious_sections:
            result.findings.append(Finding(
                detector=self.NAME,
                name="packer_section_name",
                description="Section name typical of packers",
                severity=Severity.HIGH,
                evidence=", ".join(suspicious_sections),
            ))

        # 3. Высокая энтропия в секции кода.
        for section in analysis.sections:
            is_code = (
                section.name in _CODE_SECTION_NAMES
                or "X" in section.flags  # executable flag
            )
            if is_code and section.entropy >= _HIGH_ENTROPY_THRESHOLD and section.size > 100:
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="high_entropy_code",
                    description=f"Code section has very high entropy "
                                f"({section.entropy:.2f}), suggests packing/encryption",
                    severity=Severity.HIGH,
                    evidence=f"{section.name} entropy={section.entropy:.2f}",
                ))

        # 4. Подозрительно малое количество импортов.
        # Только в комбинации с другими признаками — сам по себе слабый сигнал.
        if len(analysis.imports) < _LOW_IMPORTS_THRESHOLD and analysis.size > 10000:
            result.findings.append(Finding(
                detector=self.NAME,
                name="few_imports",
                description=f"Only {len(analysis.imports)} imports for "
                            f"{analysis.size}-byte binary — suggests dynamic loading",
                severity=Severity.MEDIUM,
                evidence=f"imports={len(analysis.imports)}, size={analysis.size}",
            ))

        return result
