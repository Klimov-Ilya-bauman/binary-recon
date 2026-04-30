"""
NetworkDetector — обнаруживает признаки сетевой активности.

Сетевая активность сама по себе НЕ является признаком вредоноса —
браузер, мессенджер, почтовый клиент тоже работают с сетью. Поэтому
severity для отдельных импортов умеренная (LOW/MEDIUM). Высокая severity
поднимается, только когда мы видим комбинацию: импорт send/recv плюс
hardcoded URL/IP в строках — это типично для C&C-связи (Command and
Control), когда вредонос связывается с управляющим сервером.

Калибровка severity для URL/IP:
  - URL на whitelist-домен (gnu.org, github.com, ...): не finding вовсе.
    Это типичные ссылки из --help выводов и документации.
  - URL на остальные домены: LOW (слабый индикатор, нужны ещё подсказки).
  - URL с подозрительными TLD/паттернами (.onion, .top, dynamic DNS): MEDIUM.
  - URL вида http://<IP>: HIGH (классика C&C).
  - "Голый" IP-адрес в строке: MEDIUM.
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

# POSIX socket — функции, реально означающие активный сетевой код.
# nss/resolver затаскивает gethostbyname/getaddrinfo, поэтому одних их мало.
_LINUX_NETWORK_ACTIVE = (
    "socket", "connect", "bind", "listen", "accept",
    "send", "recv", "sendto", "recvfrom",
)

_LINUX_NETWORK_PASSIVE = (
    "gethostbyname", "getaddrinfo",
)

_CURL_API = (
    "curl_easy_init", "curl_easy_setopt", "curl_easy_perform",
    "curl_global_init",
)

# ---- Регулярные выражения для строк ----

_URL_RE = re.compile(r'\bhttps?://[^\s"\'<>\x00-\x1f]{4,}', re.IGNORECASE)
_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
)
# Извлечение домена из URL — упрощённый паттерн.
_HOST_FROM_URL_RE = re.compile(r'^https?://([^/?#:]+)', re.IGNORECASE)


# Whitelist легитимных доменов. URL на эти домены вообще не считаем
# подозрительными — типичные ссылки в --help выводах open-source утилит,
# в документации и в строках лицензий.
_BENIGN_DOMAINS = frozenset({
    "gnu.org",
    "fsf.org",
    "kernel.org",
    "github.com",
    "gitlab.com",
    "savannah.gnu.org",
    "savannah.nongnu.org",
    "translationproject.org",
    "wiki.xiph.org",
    "xiph.org",
    "freedesktop.org",
    "python.org",
    "debian.org",
    "ubuntu.com",
    "redhat.com",
    "fedoraproject.org",
    "archlinux.org",
    "microsoft.com",
    "apple.com",
    "openssl.org",
    "boost.org",
    "cmake.org",
    "w3.org",
    "ietf.org",
    "iana.org",
    "unicode.org",
})

# Подозрительные TLD: часто используются в фишинге/малвари из-за
# дешёвой регистрации или специфики использования.
_SUSPICIOUS_TLDS = (
    ".onion",
    ".top",
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".click",
)


def _extract_host(url: str) -> str:
    """Достаёт хост из URL. Возвращает '' если не удалось распарсить."""
    m = _HOST_FROM_URL_RE.match(url)
    if not m:
        return ""
    return m.group(1).lower()


def _is_benign_host(host: str) -> bool:
    """True если host или любой из его суффиксов есть в whitelist."""
    if not host:
        return False
    if host in _BENIGN_DOMAINS:
        return True
    # Проверяем суффиксы: example.gnu.org → gnu.org должен совпасть.
    parts = host.split(".")
    for i in range(1, len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in _BENIGN_DOMAINS:
            return True
    return False


def _is_ip_host(host: str) -> bool:
    """True если host — это IPv4-адрес (а не доменное имя)."""
    return bool(_IPV4_RE.fullmatch(host))


def _is_suspicious_tld(host: str) -> bool:
    return any(host.endswith(tld) for tld in _SUSPICIOUS_TLDS)


class NetworkDetector(BaseDetector):
    NAME = "Network"

    _BENIGN_IPS = frozenset({
        "0.0.0.0", "127.0.0.1", "255.255.255.255",
        "1.0.0.0", "1.2.3.4",
    })

    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        result = DetectorResult(detector=self.NAME)

        # ---- Импорты PE/Winsock ----
        if analysis.format == "PE":
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

        # ---- Импорты ELF/POSIX ----
        # Только активные функции (socket/connect/send/...) реально означают
        # сеть. Одних gethostbyname мало — это nss/resolver, есть в любом
        # бинарнике, использующем имена пользователей через NIS/LDAP.
        if analysis.format == "ELF":
            active = self.find_imports_matching(analysis, list(_LINUX_NETWORK_ACTIVE))
            passive = self.find_imports_matching(analysis, list(_LINUX_NETWORK_PASSIVE))
            if len(active) >= 3:
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="posix_socket_api",
                    description=f"POSIX socket API ({len(active)} functions)",
                    severity=Severity.LOW,
                    evidence=", ".join(active[:5]),
                ))
            elif active:
                # 1-2 функции — может быть обычный код, может — нет.
                # Выдаём LOW finding, но с явной пометкой "partial".
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="posix_socket_partial",
                    description=f"Partial POSIX socket API ({len(active)} fn)",
                    severity=Severity.LOW,
                    evidence=", ".join(active),
                ))
            # passive (gethostbyname etc.) сам по себе не finding.

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
        for url in urls[:10]:
            host = _extract_host(url)

            # 1. Whitelist — пропускаем без finding'а.
            if _is_benign_host(host):
                continue

            evidence = url if len(url) <= 100 else url[:97] + "..."

            # 2. URL с IP вместо домена — почти всегда C&C.
            if _is_ip_host(host):
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="url_with_ip",
                    description="URL pointing directly to an IP address (typical of C&C)",
                    severity=Severity.HIGH,
                    evidence=evidence,
                ))
                continue

            # 3. Подозрительный TLD.
            if _is_suspicious_tld(host):
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="url_suspicious_tld",
                    description="URL on suspicious top-level domain",
                    severity=Severity.MEDIUM,
                    evidence=evidence,
                ))
                continue

            # 4. Обычный URL не в whitelist — слабый индикатор.
            result.findings.append(Finding(
                detector=self.NAME,
                name="hardcoded_url",
                description="Hardcoded URL in binary",
                severity=Severity.LOW,
                evidence=evidence,
            ))

        # ---- Строки: голый IPv4 ----
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
            if "version" in s.lower():
                continue
            for ip in _IPV4_RE.findall(s):
                if ip in cls._BENIGN_IPS or ip in seen:
                    continue
                seen.add(ip)
                found.append(ip)
        return found
