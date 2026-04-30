"""
SignaturesDetector — обнаруживает известные строковые паттерны вредоносов.

Это самый прямолинейный детектор: список известных подозрительных строк
проверяется на наличие в файле. Никакой эвристики, чистое сравнение.

Категории сигнатур:
  1. Имена известных вредоносов и инструментов:
     mimikatz, meterpreter, cobalt strike, empire, beacon, pupy, ...
  2. Подозрительные команды в строках:
     "cmd.exe /c", "powershell -enc", "bash -c", "wget http://..."
  3. Подозрительные пути:
     %TEMP%, %APPDATA%\\Roaming, /tmp/, /dev/shm/
  4. Двойные расширения и хитрые имена:
     ".pdf.exe", ".doc.scr"
  5. Признаки кейлоггеров: GetAsyncKeyState API.

Severity варьируется: имена малвари — CRITICAL/HIGH, подозрительные
команды — MEDIUM, общие подозрительные пути — LOW.
"""

from __future__ import annotations

from recon.core.core_wrapper import AnalysisResult
from recon.detectors.base_detector import (
    BaseDetector, DetectorResult, Finding, Severity,
)


# Имена известных малвари и offensive-инструментов.
_KNOWN_MALWARE_NAMES = (
    ("mimikatz",      "Mimikatz credential dumper"),
    ("meterpreter",   "Metasploit Meterpreter payload"),
    ("cobalt strike", "Cobalt Strike beacon"),
    ("cobaltstrike",  "Cobalt Strike beacon"),
    ("empire",        "PowerShell Empire framework"),
    ("powersploit",   "PowerSploit toolkit"),
    ("pupy",          "Pupy RAT"),
    ("quasar",        "Quasar RAT"),
    ("revil",         "REvil ransomware"),
    ("locky",         "Locky ransomware"),
)

# Подозрительные команды в строках.
_SUSPICIOUS_COMMANDS = (
    "cmd.exe /c",
    "cmd.exe /k",
    "powershell -enc",
    "powershell -encodedcommand",
    "powershell -nop",
    "powershell -windowstyle hidden",
    "iex (new-object",
    "downloadstring(",
    "wget http://",
    "curl http://",
    "/bin/sh -c",
)

# Подозрительные пути / расположения.
_SUSPICIOUS_PATHS = (
    r"\AppData\Roaming\\",
    r"\AppData\Local\Temp\\",
    "/tmp/.",       # скрытые файлы в /tmp
    "/dev/shm/",
    "C:\\Windows\\Temp\\",
)

# Двойные расширения — классика.
_DOUBLE_EXTENSIONS = (
    ".pdf.exe", ".doc.exe", ".docx.exe",
    ".jpg.exe", ".png.exe",
    ".pdf.scr", ".doc.scr",
    ".xls.exe", ".xlsx.exe",
)

# Кейлоггеры.
_KEYLOGGER_API = (
    "GetAsyncKeyState",
    "GetKeyboardState",
    "SetWindowsHookExA",  # уже в Injection — но в keylogger контексте отдельно
)


class SignaturesDetector(BaseDetector):
    NAME = "Signatures"

    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        result = DetectorResult(detector=self.NAME)

        # 1. Имена известных малвари.
        lowered_strings = [s.lower() for s in analysis.strings]
        for needle, description in _KNOWN_MALWARE_NAMES:
            if any(needle in s for s in lowered_strings):
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="known_malware_signature",
                    description=description,
                    severity=Severity.CRITICAL,
                    evidence=needle,
                ))

        # 2. Подозрительные команды.
        cmd_strings = self.find_strings_matching(analysis, list(_SUSPICIOUS_COMMANDS))
        for s in cmd_strings[:5]:
            evidence = s if len(s) <= 100 else s[:97] + "..."
            result.findings.append(Finding(
                detector=self.NAME,
                name="suspicious_command",
                description="Suspicious shell/PowerShell command pattern",
                severity=Severity.HIGH,
                evidence=evidence,
            ))

        # 3. Двойные расширения.
        for ext in _DOUBLE_EXTENSIONS:
            if any(ext in s for s in analysis.strings):
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="double_extension",
                    description="Double-extension filename (social engineering)",
                    severity=Severity.HIGH,
                    evidence=ext,
                ))

        # 4. Подозрительные пути.
        path_strings = self.find_strings_matching(analysis, list(_SUSPICIOUS_PATHS))
        # Берём только уникальные пути, не более 5 findings
        seen_paths: set[str] = set()
        for s in path_strings:
            for path in _SUSPICIOUS_PATHS:
                if path in s and path not in seen_paths:
                    seen_paths.add(path)
                    result.findings.append(Finding(
                        detector=self.NAME,
                        name="suspicious_path",
                        description="Suspicious path reference",
                        severity=Severity.LOW,
                        evidence=path.strip("\\"),
                    ))
                    break
            if len(seen_paths) >= 5:
                break

        # 5. Keylogger API.
        keylogger = self.find_imports_matching(analysis, list(_KEYLOGGER_API))
        # SetWindowsHookEx уже учтён Injection-детектором, тут другие.
        keylogger_only = [k for k in keylogger if "Hook" not in k]
        if keylogger_only:
            result.findings.append(Finding(
                detector=self.NAME,
                name="keylogger_api",
                description="Keystroke monitoring API",
                severity=Severity.HIGH,
                evidence=", ".join(keylogger_only),
            ))

        return result
