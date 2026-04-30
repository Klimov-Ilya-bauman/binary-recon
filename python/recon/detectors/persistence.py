"""
PersistenceDetector — обнаруживает попытки закрепиться в системе.

После заражения вредонос хочет выживать перезагрузки. Для этого он
прописывает себя в одно из мест автозапуска. На Windows это:
  - Реестр: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
  - Реестр: HKLM\\...\\Run, RunOnce, Winlogon\\Userinit
  - Службы (Services), запланированные задачи (Task Scheduler)
  - Папки автозагрузки: %APPDATA%\\Microsoft\\Windows\\Start Menu\\
                        Programs\\Startup

На Linux:
  - cron / crontab
  - systemd services (~/.config/systemd/user/)
  - .bashrc, .profile, .bash_aliases
  - /etc/init.d/ (старый SysV)
  - /etc/rc.local

Признак подозрительный, но не обязательно вредоносный — легитимные
программы тоже устанавливают автозапуск (антивирусы, мессенджеры).
Поэтому severity MEDIUM, а HIGH только при комбинации с другими
индикаторами.
"""

from __future__ import annotations

from recon.core.core_wrapper import AnalysisResult
from recon.detectors.base_detector import (
    BaseDetector, DetectorResult, Finding, Severity,
)


# ---- Windows API ----

_REGISTRY_API = (
    "RegOpenKeyA", "RegOpenKeyW", "RegOpenKeyExA", "RegOpenKeyExW",
    "RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyExA", "RegCreateKeyExW",
    "RegSetValueA", "RegSetValueW", "RegSetValueExA", "RegSetValueExW",
)

_SERVICE_API = (
    "OpenSCManagerA", "OpenSCManagerW",
    "CreateServiceA", "CreateServiceW",
    "StartServiceA", "StartServiceW",
    "ChangeServiceConfigA", "ChangeServiceConfigW",
)

_TASK_SCHEDULER_API = (
    # COM-интерфейс к Task Scheduler редко напрямую виден в импортах,
    # но schtasks вызывается через CreateProcess + командная строка
    "ITaskScheduler", "ITaskService",
)

# ---- Подстроки в строках ----

# Windows — пути реестра и автозагрузки.
_WINDOWS_PERSISTENCE_STRINGS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"System\CurrentControlSet\Services",
    r"\Start Menu\Programs\Startup",
    "schtasks /create",
    "schtasks.exe",
)

# Linux — пути и команды.
_LINUX_PERSISTENCE_STRINGS = (
    "/etc/cron",
    "crontab -e",
    "/etc/init.d/",
    "/etc/rc.local",
    "/.bashrc",
    "/.bash_profile",
    "systemctl enable",
    "/etc/systemd/system/",
    "/.config/autostart/",
)


class PersistenceDetector(BaseDetector):
    NAME = "Persistence"

    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        result = DetectorResult(detector=self.NAME)

        # ---- Импорты ----
        reg_imports = self.find_imports_matching(analysis, list(_REGISTRY_API))
        # RegSetValue* — самый сильный индикатор, потому что чтение реестра
        # делают все, а запись — только если хочешь что-то изменить.
        write_apis = [fn for fn in reg_imports if "Set" in fn or "Create" in fn]
        if write_apis:
            result.findings.append(Finding(
                detector=self.NAME,
                name="registry_write",
                description="Registry write API — possible autostart configuration",
                severity=Severity.MEDIUM,
                evidence=", ".join(write_apis[:5]),
            ))

        svc_api = self.find_imports_matching(analysis, list(_SERVICE_API))
        if svc_api:
            result.findings.append(Finding(
                detector=self.NAME,
                name="service_install",
                description="Windows Service installation API",
                severity=Severity.HIGH,
                evidence=", ".join(svc_api[:5]),
            ))

        # ---- Строки ----
        win_strings = self.find_strings_matching(
            analysis, list(_WINDOWS_PERSISTENCE_STRINGS))
        for s in win_strings[:5]:
            evidence = s if len(s) <= 80 else s[:77] + "..."
            result.findings.append(Finding(
                detector=self.NAME,
                name="autostart_path",
                description="Windows autostart path/key reference",
                severity=Severity.MEDIUM,
                evidence=evidence,
            ))

        linux_strings = self.find_strings_matching(
            analysis, list(_LINUX_PERSISTENCE_STRINGS))
        for s in linux_strings[:5]:
            evidence = s if len(s) <= 80 else s[:77] + "..."
            result.findings.append(Finding(
                detector=self.NAME,
                name="linux_autostart",
                description="Linux persistence mechanism reference",
                severity=Severity.MEDIUM,
                evidence=evidence,
            ))

        return result
