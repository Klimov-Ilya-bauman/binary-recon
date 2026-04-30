"""
CryptoDetector — обнаруживает использование криптографии.

Криптография в бинарнике сама по себе не преступление — TLS-клиенты,
менеджеры паролей, мессенджеры её используют постоянно. Но в контексте
малвари это сильный индикатор:
  - Ransomware шифрует файлы пользователя.
  - C&C-протокол шифрует трафик, чтобы скрыть его от анализа.
  - Malware шифрует свою конфигурацию или payload, чтобы антивирусы
    не могли просканировать содержимое.

Детектируем по двум каналам:
  1. Импорты криптографических API (CryptoAPI, BCrypt, OpenSSL).
  2. Сигнатуры алгоритмов в строках/коде. Например, AES использует
     S-box — таблицу подстановки из 256 фиксированных байт. Эти 256 байт
     стандартизированы, и если они есть в бинарнике — почти наверняка
     там реализован AES.

S-box детекция здесь не реализована — это более продвинутая техника
(нужно искать байтовый паттерн в .rodata, а у нас сейчас .rodata
не выделена отдельно). Сделаем по импортам и строкам — этого достаточно
для базового детектора.
"""

from __future__ import annotations

from recon.core.core_wrapper import AnalysisResult
from recon.detectors.base_detector import (
    BaseDetector, DetectorResult, Finding, Severity,
)


# Старый Windows CryptoAPI (CAPI).
_CRYPTOAPI = (
    "CryptAcquireContextA", "CryptAcquireContextW",
    "CryptEncrypt", "CryptDecrypt",
    "CryptHashData", "CryptCreateHash",
    "CryptGenKey", "CryptDeriveKey",
    "CryptReleaseContext",
)

# Современный Windows CNG/BCrypt (Vista+).
_BCRYPT = (
    "BCryptEncrypt", "BCryptDecrypt",
    "BCryptHashData", "BCryptCreateHash",
    "BCryptGenerateKeyPair", "BCryptGenerateSymmetricKey",
    "BCryptOpenAlgorithmProvider",
)

# OpenSSL / libcrypto (Linux, Windows).
_OPENSSL = (
    "EVP_EncryptInit", "EVP_EncryptUpdate", "EVP_EncryptFinal",
    "EVP_DecryptInit", "EVP_DecryptUpdate", "EVP_DecryptFinal",
    "EVP_CIPHER_CTX_new",
    "AES_set_encrypt_key", "AES_encrypt",
    "RSA_new", "RSA_public_encrypt",
    "SSL_CTX_new", "SSL_connect",
)

# Сигнатуры алгоритмов в строках.
_CRYPTO_STRING_SIGNATURES = (
    ("AES-",        "AES"),
    ("aes-256",     "AES-256"),
    ("RSA-",        "RSA"),
    ("ChaCha20",    "ChaCha20"),
    ("salsa20",     "Salsa20"),
    ("SHA-256",     "SHA-256"),
    ("SHA-512",     "SHA-512"),
    ("PKCS",        "PKCS standard"),
)

# Расширения шифрованных файлов — типично для ransomware.
_RANSOMWARE_EXTENSIONS = (
    ".locked", ".encrypted", ".crypto", ".crypt",
    ".ransom", ".pay", ".cry",
)


class CryptoDetector(BaseDetector):
    NAME = "Crypto"

    def detect(self, analysis: AnalysisResult) -> DetectorResult:
        result = DetectorResult(detector=self.NAME)

        # ---- Импорты ----
        capi = self.find_imports_matching(analysis, list(_CRYPTOAPI))
        if capi:
            result.findings.append(Finding(
                detector=self.NAME,
                name="windows_cryptoapi",
                description="Windows CryptoAPI (CAPI)",
                severity=Severity.MEDIUM,
                evidence=", ".join(capi[:5]),
            ))

        bcrypt = self.find_imports_matching(analysis, list(_BCRYPT))
        if bcrypt:
            result.findings.append(Finding(
                detector=self.NAME,
                name="windows_bcrypt",
                description="Windows CNG (BCrypt) cryptography",
                severity=Severity.MEDIUM,
                evidence=", ".join(bcrypt[:5]),
            ))

        openssl = self.find_imports_matching(analysis, list(_OPENSSL))
        if openssl:
            result.findings.append(Finding(
                detector=self.NAME,
                name="openssl_libcrypto",
                description="OpenSSL/libcrypto cryptographic library",
                severity=Severity.MEDIUM,
                evidence=", ".join(openssl[:5]),
            ))

        # ---- Сигнатуры в строках ----
        for signature, algo_name in _CRYPTO_STRING_SIGNATURES:
            if any(signature.lower() in s.lower() for s in analysis.strings):
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="crypto_algorithm_string",
                    description=f"{algo_name} algorithm reference in strings",
                    severity=Severity.LOW,
                    evidence=signature,
                ))

        # ---- Ransomware-расширения ----
        for ext in _RANSOMWARE_EXTENSIONS:
            if any(ext in s for s in analysis.strings):
                result.findings.append(Finding(
                    detector=self.NAME,
                    name="ransomware_extension",
                    description="File extension typical of ransomware",
                    severity=Severity.HIGH,
                    evidence=ext,
                ))

        return result
