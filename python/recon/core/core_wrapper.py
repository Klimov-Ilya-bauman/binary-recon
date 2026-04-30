"""
CoreWrapper — мост между Python-слоем и скомпилированным C++ ядром.

Вызывает бинарник `core` через subprocess, передаёт ему путь к анализируемому
файлу, ловит JSON со stdout и парсит в типизированные dataclasses.

Все ошибки C++ ядра (отсутствует, упал, не отвечает в таймаут, выдал кривой
JSON) превращаются в осмысленные Python-исключения CoreError и подклассы.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# =============================================================================
#                              EXCEPTIONS
# =============================================================================

class CoreError(Exception):
    """Базовое исключение для всех проблем взаимодействия с C++ ядром."""


class CoreNotFoundError(CoreError):
    """Бинарник `core` не найден в файловой системе."""


class CoreTimeoutError(CoreError):
    """C++ ядро не ответило за отведённое время."""


class CoreExecutionError(CoreError):
    """Бинарник запустился, но завершился с ненулевым кодом."""


class CoreOutputError(CoreError):
    """Бинарник выдал stdout, который не является валидным JSON."""


class UnsupportedFormatError(CoreError):
    """Файл не распознан как ELF или PE."""


# =============================================================================
#                              DATA STRUCTURES
# =============================================================================

@dataclass
class Section:
    """Универсальный класс секции — общий для ELF и PE."""
    name: str
    address: int          # для ELF — sh_addr, для PE — VirtualAddress (RVA)
    size: int             # размер секции (sh_size или VirtualSize)
    raw_offset: int       # смещение в файле
    flags: str            # строковое представление: "AX", "RWX" и т.п.
    entropy: float


@dataclass
class Import:
    """
    Один импортируемый символ. Для ELF поле `dll` остаётся пустым,
    потому что в ELF импорты не группируются по библиотекам в .dynsym.
    Для PE — DLL обязательна (KERNEL32.dll, msvcrt.dll, ...).
    """
    function: str
    dll: str = ""

    @property
    def is_pe_import(self) -> bool:
        return bool(self.dll)


@dataclass
class AnalysisResult:
    """
    Результат парсинга бинарного файла C++ ядром.

    Это типизированное представление JSON-ответа от `./core <file> --json`.
    Все детекторы получают именно этот объект и работают с его полями.
    """
    schema_version: str
    format: str                          # "ELF" или "PE"
    filepath: str
    size: int
    md5: str
    sha256: str
    entropy: float                       # энтропия всего файла

    # Метаданные формата (для ELF и PE могут отличаться).
    arch: str = ""
    bits: int = 0                        # 32 или 64 (elf_class или pe_class)
    endianness: str = ""                 # "little" / "big" (только ELF)
    file_type: str = ""                  # "EXEC"/"DYN" (ELF) или "console"/"gui" (PE)
    entry_point: int = 0
    image_base: int = 0                  # только PE

    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    string_count: int = 0


# =============================================================================
#                              CORE WRAPPER
# =============================================================================

# Кандидаты для поиска C++ бинарника. Проверяются по порядку.
_CORE_BINARY_NAME = "core"

# Если не находим — будем кидать CoreNotFoundError с инструкцией.
_BUILD_HINT = (
    "C++ core binary not found. Build it with:\n"
    "  cd <repo>/core/build && cmake .. && make\n"
    "Or set environment variable RECON_CORE_PATH to its full path."
)


def _find_core_binary() -> Path:
    """
    Ищет скомпилированный C++ бинарник `core` в нескольких местах.

    Порядок поиска:
      1. Переменная окружения RECON_CORE_PATH (явное переопределение).
      2. <repo>/core/build/core (стандартное место для dev-сборки).
      3. /usr/local/lib/binary-recon/core (после `make install`).
      4. /usr/lib/binary-recon/core (после установки .deb пакета).
    """
    # 1. Env override
    env_path = os.environ.get("RECON_CORE_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file() and os.access(p, os.X_OK):
            return p
        raise CoreNotFoundError(
            f"RECON_CORE_PATH points to {env_path}, but file is missing or not executable."
        )

    # 2. Dev-режим: ищем относительно текущего файла.
    # __file__ = python/recon/core/core_wrapper.py
    # repo root = parent[3]
    repo_root = Path(__file__).resolve().parents[3]
    dev_path = repo_root / "core" / "build" / _CORE_BINARY_NAME
    if dev_path.is_file() and os.access(dev_path, os.X_OK):
        return dev_path

    # 3. После make install
    for candidate in (
        Path("/usr/local/lib/binary-recon") / _CORE_BINARY_NAME,
        Path("/usr/lib/binary-recon") / _CORE_BINARY_NAME,
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate

    raise CoreNotFoundError(_BUILD_HINT)


def _parse_section(raw: dict, format_: str) -> Section:
    """Парсинг одной секции из JSON. ELF и PE используют немного разные поля."""
    if format_ == "PE":
        return Section(
            name=raw.get("name", ""),
            address=int(raw.get("virtual_address", "0x0"), 16) if isinstance(
                raw.get("virtual_address"), str) else int(raw.get("virtual_address", 0)),
            size=int(raw.get("virtual_size", 0)),
            raw_offset=int(raw.get("raw_offset", 0)),
            flags=raw.get("flags", ""),
            entropy=float(raw.get("entropy", 0.0)),
        )
    # ELF
    return Section(
        name=raw.get("name", ""),
        address=int(raw.get("address", "0x0"), 16) if isinstance(
            raw.get("address"), str) else int(raw.get("address", 0)),
        size=int(raw.get("size", 0)),
        raw_offset=int(raw.get("offset", 0)),
        flags=raw.get("flags", ""),
        entropy=float(raw.get("entropy", 0.0)),
    )


def _parse_import(raw, format_: str) -> Import:
    """Импорты в ELF — строки, в PE — объекты {dll, function}."""
    if format_ == "PE":
        return Import(function=raw.get("function", ""), dll=raw.get("dll", ""))
    return Import(function=str(raw))


def _hex_or_int(value) -> int:
    """JSON может содержать адрес как '0x1234' или как число — нормализуем."""
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    if isinstance(value, int):
        return value
    return 0


def _parse_analysis_result(raw: dict) -> AnalysisResult:
    """JSON dict → AnalysisResult."""
    fmt = raw.get("format", "")

    result = AnalysisResult(
        schema_version=raw.get("schema_version", ""),
        format=fmt,
        filepath=raw.get("filepath", ""),
        size=int(raw.get("size", 0)),
        md5=raw.get("md5", ""),
        sha256=raw.get("sha256", ""),
        entropy=float(raw.get("entropy", 0.0)),
        arch=raw.get("arch", ""),
        entry_point=_hex_or_int(raw.get("entry_point", 0)),
        string_count=int(raw.get("string_count", 0)),
    )

    if fmt == "ELF":
        result.bits = int(raw.get("elf_class", 0))
        result.endianness = raw.get("endianness", "")
        result.file_type = raw.get("type", "")
    elif fmt == "PE":
        result.bits = int(raw.get("pe_class", 0))
        result.endianness = "little"  # PE всегда little-endian
        result.file_type = raw.get("subsystem", "")
        result.image_base = _hex_or_int(raw.get("image_base", 0))

    for s in raw.get("sections", []):
        result.sections.append(_parse_section(s, fmt))
    for i in raw.get("imports", []):
        result.imports.append(_parse_import(i, fmt))
    result.strings = list(raw.get("strings", []))

    return result


class CoreWrapper:
    """
    Высокоуровневая обёртка вокруг вызова C++ бинарника.

    Использование:
        wrapper = CoreWrapper()
        result = wrapper.analyze("/bin/ls")
    """

    DEFAULT_TIMEOUT_SECONDS = 30.0

    def __init__(self, core_path: Optional[Path] = None,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.core_path = core_path or _find_core_binary()
        self.timeout = timeout

    def analyze(self, filepath: str) -> AnalysisResult:
        """
        Запускает C++ ядро на файле и возвращает разобранный результат.

        Raises:
            FileNotFoundError: если анализируемый файл не существует.
            CoreTimeoutError: ядро не уложилось в таймаут.
            CoreExecutionError: ядро вернуло ненулевой код.
            CoreOutputError: stdout не парсится как JSON.
            UnsupportedFormatError: формат файла не ELF и не PE.
        """
        target = Path(filepath)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {filepath}")

        try:
            completed = subprocess.run(
                [str(self.core_path), str(target.resolve()), "--json"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise CoreTimeoutError(
                f"Core did not finish within {self.timeout}s on {filepath}"
            ) from e

        # Сначала пробуем распарсить stdout — даже при ненулевом exit code
        # ядро может выдать осмысленный JSON-объект с ключом "error".
        stdout = completed.stdout.strip()
        if not stdout:
            raise CoreExecutionError(
                f"Core returned empty output (exit code {completed.returncode}). "
                f"stderr: {completed.stderr.strip()}"
            )

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise CoreOutputError(f"Invalid JSON from core: {e}") from e

        if "error" in raw:
            raise UnsupportedFormatError(raw["error"])

        if completed.returncode != 0:
            raise CoreExecutionError(
                f"Core failed with exit code {completed.returncode}: "
                f"{completed.stderr.strip()}"
            )

        return _parse_analysis_result(raw)
