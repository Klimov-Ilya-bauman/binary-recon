"""
AntiDebugDetector — обнаруживает признаки противодействия отладке.

Anti-debugging — техника, которой вредоносы пользуются, чтобы затруднить
анализ. Программа проверяет: нахожусь ли я под отладчиком? Если да —
прекращает выполнение, делает ошибочные вычисления, или отправляет
поддельные данные. Это сильный индикатор того, что автор не хочет,
чтобы программу разбирали.

Что детектор ищет:

  Windows (PE):
    - IsDebuggerPresent       — проверка флага в PEB через WinAPI
    - CheckRemoteDebuggerPresent — то же для другого процесса
    - NtQueryInformationProcess — низкоуровневая проверка через ntdll
    - OutputDebugStringA/W    — записывает в дебаггер, по реакции
                                 определяет его наличие
    - GetTickCount/QueryPerformanceCounter — таймерные anti-debug трюки

  Linux (ELF):
    - ptrace                  — единственный официальный API отладки
                                 в Linux; PTRACE_TRACEME мешает gdb
    - prctl                   — может использоваться с PR_SET_DUMPABLE
                                 для anti-debug

  Строки (любая платформа):
    - имена популярных отладчиков: ollydbg, x64dbg, ida, gdb, lldb,
      windbg, immunity — программа их активно ищет, чтобы избежать.
"""

from __future__ import annotations

from recon.core.core_wrapper import AnalysisResult
from recon.detectors.base_detector import (
    BaseDetector, DetectorResult, Finding, Severity,
)


# ---- Импорты, считающиеся anti-debug ----

_WINDOWS_HIGH = (
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "DebugActiveProcess",
)

_WINDOWS_MEDIUM = (
    "OutputDebugStringA",
    "OutputDebugStringW",
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
)

_LINUX_HIGH = (
    "ptrace",
)

_LINUX_MEDIUM = (
    "prctl",
)

# ---- Подстроки в строках, индикаторы anti-debug ----

_DEBUGGER_NAMES = (
    "ollydbg",
    "x64dbg",
    "x32dbg",
    "ida.exe",
    "ida64.exe",
    "windbg",
    "immunitydebugger",
    "lldb",
    # "gdb" слишком общее (встретится в строках обычного glibc),
    # поэтому не добавляем его сюда — даст много false positive.
)


class AntiDebugDetector(BaseDetector):
    NAME = "AntiDebug"

    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        result = DetectorResult(detector=self.NAME)

        # 1. Импорты — высокая severity для прямых WinAPI/syscalls.
        for fn in self.find_imports_matching(analysis, list(_WINDOWS_HIGH)):
            result.findings.append(Finding(
                detector=self.NAME,
                name="anti_debug_winapi",
                description=f"Windows anti-debug API import: {fn}",
                severity=Severity.HIGH,
                evidence=fn,
            ))

        for fn in self.find_imports_matching(analysis, list(_LINUX_HIGH)):
            result.findings.append(Finding(
                detector=self.NAME,
                name="anti_debug_ptrace",
                description=f"Linux anti-debug syscall: {fn}",
                severity=Severity.HIGH,
                evidence=fn,
            ))

        # 2. Импорты с косвенным anti-debug потенциалом — MEDIUM.
        for fn in self.find_imports_matching(analysis, list(_WINDOWS_MEDIUM)):
            result.findings.append(Finding(
                detector=self.NAME,
                name="anti_debug_indirect",
                description=f"Indirect anti-debug API: {fn}",
                severity=Severity.MEDIUM,
                evidence=fn,
            ))

        for fn in self.find_imports_matching(analysis, list(_LINUX_MEDIUM)):
            result.findings.append(Finding(
                detector=self.NAME,
                name="anti_debug_indirect",
                description=f"Indirect anti-debug syscall: {fn}",
                severity=Severity.MEDIUM,
                evidence=fn,
            ))

        # 3. Упоминания отладчиков в строках — LOW (могут быть false positive,
        # но в комбинации с импортами усиливают подозрение).
        for s in self.find_strings_matching(analysis, list(_DEBUGGER_NAMES)):
            # Ограничим evidence-строку, чтобы не раздувать вывод.
            evidence = s if len(s) <= 80 else s[:77] + "..."
            result.findings.append(Finding(
                detector=self.NAME,
                name="debugger_string",
                description="Reference to known debugger in strings",
                severity=Severity.LOW,
                evidence=evidence,
            ))

        return result
