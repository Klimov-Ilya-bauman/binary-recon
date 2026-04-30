"""
InjectionDetector — обнаруживает признаки code injection.

Code injection — техника, при которой код одного процесса выполняется
в адресном пространстве другого процесса. Зачем вредоносу инжектиться:
  - Скрыться: антивирус видит легитимный процесс (например, explorer.exe),
    не зная что внутри него работает чужой код.
  - Получить привилегии: инжект в процесс с правами админа.
  - Обойти firewall: инжект в браузер — теперь "браузер" связывается
    с интернетом, и firewall это разрешает.

Классическая Windows-инжекция требует трёх API в связке:
  1. OpenProcess(...)         — получить handle на чужой процесс.
  2. VirtualAllocEx(...)      — выделить память в чужом процессе.
  3. WriteProcessMemory(...)  — записать туда наш код.
  4. CreateRemoteThread(...)  — запустить выполнение этого кода.

Наличие всех четырёх API в одном бинарнике — почти однозначный признак
вредоноса: легитимных причин для такой комбинации очень мало (отладчики,
антивирусы — но они подписаны и редкие). Один импорт сам по себе слабый
сигнал, но связка драматически усиливает severity.

Linux-аналоги: ptrace + mprotect + memcpy в /proc/PID/mem — труднее
реализуемо, но возможно.

Также детектируется DLL injection через SetWindowsHookEx и AppInit_DLLs.
"""

from __future__ import annotations

from recon.core.core_wrapper import AnalysisResult
from recon.detectors.base_detector import (
    BaseDetector, DetectorResult, Finding, Severity,
)


# Классическая Windows-инжекция.
_INJECTION_TRIAD = (
    "OpenProcess",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
)

# DLL injection / hooking.
_HOOKING_API = (
    "SetWindowsHookExA", "SetWindowsHookExW",
    "QueueUserAPC", "NtQueueApcThread",
)

# LoadLibrary в чужой процесс — старая, но рабочая техника.
_LOAD_LIBRARY = (
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
)

# Reflective DLL loading через манипуляции с памятью.
_MEMORY_MANIPULATION = (
    "VirtualProtect", "VirtualProtectEx",
    "VirtualAlloc",
)


class InjectionDetector(BaseDetector):
    NAME = "Injection"

    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        result = DetectorResult(detector=self.NAME)

        # 1. Триада инжекции — самый сильный признак.
        triad_found = self.find_imports_matching(analysis, list(_INJECTION_TRIAD))

        if len(triad_found) >= 3:
            # 3+ из 5 функций инжекции в одном бинарнике — почти однозначно вредонос.
            result.findings.append(Finding(
                detector=self.NAME,
                name="injection_triad",
                description=f"Process injection API combo ({len(triad_found)}/5)",
                severity=Severity.CRITICAL,
                evidence=", ".join(triad_found),
            ))
        elif triad_found:
            # 1-2 функции — подозрительно, но не однозначно.
            result.findings.append(Finding(
                detector=self.NAME,
                name="injection_partial",
                description="Partial process injection API set",
                severity=Severity.MEDIUM,
                evidence=", ".join(triad_found),
            ))

        # 2. Hooking — отдельная техника инжекции.
        hooks = self.find_imports_matching(analysis, list(_HOOKING_API))
        if hooks:
            result.findings.append(Finding(
                detector=self.NAME,
                name="hooking_api",
                description="Windows hook installation API",
                severity=Severity.HIGH,
                evidence=", ".join(hooks),
            ))

        # 3. LoadLibrary + WriteProcessMemory — классика DLL injection.
        load_lib = self.find_imports_matching(analysis, list(_LOAD_LIBRARY))
        if load_lib and "WriteProcessMemory" in triad_found:
            result.findings.append(Finding(
                detector=self.NAME,
                name="dll_injection_pattern",
                description="LoadLibrary + WriteProcessMemory — DLL injection",
                severity=Severity.HIGH,
                evidence=f"{load_lib[0]} + WriteProcessMemory",
            ))

        # 4. VirtualProtect — manipulation памяти, может быть RWX-аллокация.
        # Само по себе не криминал (JIT-компиляторы используют), поэтому LOW.
        mem_manip = self.find_imports_matching(analysis, list(_MEMORY_MANIPULATION))
        if mem_manip:
            result.findings.append(Finding(
                detector=self.NAME,
                name="memory_manipulation",
                description="Runtime memory protection manipulation",
                severity=Severity.LOW,
                evidence=", ".join(mem_manip),
            ))

        return result
