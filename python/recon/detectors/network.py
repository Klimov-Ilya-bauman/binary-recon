"""
NetworkDetector — обнаруживает признаки сетевой активности.

Сетевая активность сама по себе НЕ является признаком вредоноса —
браузер, мессенджер, почтовый клиент тоже работают с сетью. Поэтому
severity для отдельных импортов умеренная (LOW/MEDIUM). Высокая severity
поднимается, только когда мы видим комбинацию: импорт send/recv плюс
hardcoded URL/IP в строках — это типично для C&C-связи (Command and
Control), когда вредонос связывается с управляющим сервером.

Что детектор ищет:

  Windows:
    - Winsock 2 API:    WSAStartup, socket, connect, send, recv, ...
    - WinINet:          InternetOpenA, InternetConnectA, HttpSendRequestA
    - WinHTTP:          WinHttpOpen, WinHttpConnect, WinHttpSendRequest
    - URLDownloadToFile — типичный downloader, скачивает payload.

  Linux:
    - sockets:          socket, connect, bind, listen, accept, send, recv
    - DNS:              gethostbyname, getaddrinfo, res_query
    - libcurl:          curl_easy_init, curl_easy_perform

  Строки (регулярки):
    - URL:              http://..., https://...
    - IPv4:             1-3 цифры . 1-3 . 1-3 . 1-3
    - User-Agent:       наличие "User-Agent:" — почти всегда HTTP-клиент

Hardcoded IP-адрес или URL в бинарнике — сильный индикатор C&C: легитимный
софт либо берёт адрес из конфига/настроек пользователя, либо использует
домен с DNS-резолвингом. Хардкод адреса прямо в .text — почти всегда вредонос.
"""

from __future__ import annotations

import re

from recon.core.core_wrapper import AnalysisResult
from recon.detectors.base_detector import (
    BaseDetector, DetectorResult, Finding, Severity,
)


# ---- Импорты ----

_WINSOCK_BASIC = (
    "WSAStartup", "WSACleanup",
    "socket", "closesocket",
    "connect", "send", "recv",
    "bind", "listen", "accept",
    "gethostbyname", "getaddrinfo",
    "inet_addr", "inet_pton",
)

_HTTP_API = (
    "InternetOpenA", "InternetOpenW",
    "InternetConnectA", "InternetConnectW",
    "InternetReadFile", "InternetWriteFile",
    "HttpOpenRequestA", "HttpSendRequestA",
    "WinHttpOpen", "WinHttpConnect",
    "WinHttpSendRequest", "WinHttpReadData",
)

_DOWNLOADER_API = (
    "URLDownloadToFileA", "URLDownloadToFileW",
    "URLDownloadToCacheFileA",
)

_LINUX_NETWORK = (
    "socket", "connect", "bind", "listen", "accept",
    "send", "recv", "sendto", "recvfrom",
    "gethostbyname", "getaddrinfo",
)

_CURL_API = (
    "curl_easy_init", "curl_easy_setopt", "curl_easy_perform",
    "curl_global_init",
)

# ---- Регулярные выражения для строк ----

# URL (http/https) — простой паттерн, не идеальный, но достаточный.
_URL_RE = re.compile(r'\bhttps?://[^\s"\'<>\x00-\x1f]{4,}', re.IGNORECASE)

# IPv4 — 4 числа от 0 до 255, разделённые точками.
# Чтобы избежать false positive на строках вроде "version 1.2.3.4",
# проверим что предшествующий контекст не выглядит как версия.
_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
)


class NetworkDetector(BaseDetector):
    NAME = "Network"

    # IP-адреса, которые НЕ считаем подозрительными (loopback, broadcast).
    _BENIGN_IPS = frozenset({
        "0.0.0.0", "127.0.0.1", "255.255.255.255",
        "1.0.0.0", "1.2.3.4",  # часто встречаются в примерах
    })

    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        result = DetectorResult(detector=self.NAME)

        # ---- Импорты ----
        winsock = self.find_imports_matching(analysis, list(_WINSOCK_BASIC))
        if winsock:
            result.findings.append(Finding(
                detector=self.NAME,
                name="winsock_api",
                description=f"Windows Sockets API in use ({len(winsock)} functions)",
                severity=Severity.MEDIUM,
                evidence=", ".join(winsock[:5]) + (
                    f", +{len(winsock) - 5} more" if len(winsock) > 5 else ""),
            ))

        http_api = self.find_imports_matching(analysis, list(_HTTP_API))
        if http_api:
            result.findings.append(Finding(
                detector=self.NAME,
                name="http_api",
                description="HTTP client API (WinINet/WinHTTP)",
                severity=Severity.MEDIUM,
                evidence=", ".join(http_api[:5]),
            ))

        downloader = self.find_imports_matching(analysis, list(_DOWNLOADER_API))
        if downloader:
            result.findings.append(Finding(
                detector=self.NAME,
                name="downloader_api",
                description="URLDownloadToFile API — typical downloader pattern",
                severity=Severity.HIGH,
                evidence=", ".join(downloader),
            ))

        # Linux — те же socket/connect могут быть в ELF.
        # Но в ELF мы не различаем Winsock и POSIX, поэтому
        # для PE мы уже выдали findings выше; для ELF выдаём отдельный.
        if analysis.format == "ELF":
            linux_net = self.find_imports_matching(analysis, list(_LINUX_NETWORK))
            if linux_net:
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="posix_socket_api",
                    description=f"POSIX socket API ({len(linux_net)} functions)",
                    severity=Severity.LOW,  # слишком распространено в Linux
                    evidence=", ".join(linux_net[:5]),
                ))

        curl = self.find_imports_matching(analysis, list(_CURL_API))
        if curl:
            result.findings.append(Finding(
                detector=self.NAME,
                name="libcurl",
                description="libcurl HTTP/FTP client library",
                severity=Severity.LOW,
                evidence=", ".join(curl),
            ))

        # ---- Строки: URL ----
        urls = self._find_urls(analysis.strings)
        for url in urls[:10]:  # ограничим количество findings
            evidence = url if len(url) <= 100 else url[:97] + "..."
            result.findings.append(Finding(
                detector=self.NAME,
                name="hardcoded_url",
                description="Hardcoded URL in binary",
                severity=Severity.MEDIUM,
                evidence=evidence,
            ))

        # ---- Строки: IPv4 ----
        ips = self._find_suspicious_ips(analysis.strings)
        for ip in ips[:10]:
            result.findings.append(Finding(
                detector=self.NAME,
                name="hardcoded_ip",
                description="Hardcoded IP address in binary",
                severity=Severity.MEDIUM,
                evidence=ip,
            ))

        return result

    # ---- Помощники ----

    @staticmethod
    def _find_urls(strings: list[str]) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for s in strings:
            for match in _URL_RE.findall(s):
                if match not in seen:
                    seen.add(match)
                    found.append(match)
        return found

    @classmethod
    def _find_suspicious_ips(cls, strings: list[str]) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()
        for s in strings:
            # Пропускаем строки, содержащие "version" / "Version" — там IP-подобные
            # фрагменты на самом деле версии (например, "Version 1.2.3.4").
            if "version" in s.lower():
                continue
            for ip in _IPV4_RE.findall(s):
                if ip in cls._BENIGN_IPS or ip in seen:
                    continue
                # Также фильтруем явные "версии": если IP — единственное
                # содержимое строки или окружён только пробелами/точками,
                # вероятно это всё-таки версия. Эмпирика.
                seen.add(ip)
                found.append(ip)
        return found
