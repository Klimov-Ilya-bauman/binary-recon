"""Юнит-тесты детекторов на синтетических AnalysisResult."""

from __future__ import annotations

import pytest


def make_analysis(*, imports=None, strings=None, format_="PE", sections=None):
    """Фабрика синтетических AnalysisResult."""
    from recon.core.core_wrapper import AnalysisResult, Import, Section

    a = AnalysisResult(
        schema_version="1.0", format=format_, filepath="/tmp/test",
        size=10000, md5="0" * 32, sha256="0" * 64,
        entropy=5.5, arch="x86_64", bits=64,
    )
    a.imports = [Import(function=fn, dll=dll) for fn, dll in (imports or [])]
    a.strings = list(strings or [])
    a.sections = list(sections or [])
    return a


def test_antidebug_catches_isdebuggerpresent():
    from recon.detectors.anti_debug import AntiDebugDetector
    a = make_analysis(imports=[("IsDebuggerPresent", "KERNEL32.dll")])
    result = AntiDebugDetector().detect(a)
    assert any("IsDebuggerPresent" in f.evidence for f in result.findings)


def test_antidebug_ignores_clean():
    from recon.detectors.anti_debug import AntiDebugDetector
    a = make_analysis(imports=[("printf", "msvcrt.dll")])
    result = AntiDebugDetector().detect(a)
    assert result.is_clean


def test_network_detects_url_with_ip():
    from recon.detectors.network import NetworkDetector
    a = make_analysis(strings=["http://192.168.13.37/cmd"])
    result = NetworkDetector().detect(a)
    assert any(f.severity.name == "HIGH" for f in result.findings)


def test_network_whitelists_gnu_org():
    from recon.detectors.network import NetworkDetector
    a = make_analysis(strings=["https://www.gnu.org/software/coreutils/"])
    result = NetworkDetector().detect(a)
    assert result.is_clean, f"Got: {[f.description for f in result.findings]}"


def test_injection_triad_critical():
    from recon.detectors.injection import InjectionDetector
    a = make_analysis(imports=[
        ("OpenProcess",       "KERNEL32.dll"),
        ("VirtualAllocEx",    "KERNEL32.dll"),
        ("WriteProcessMemory","KERNEL32.dll"),
    ])
    result = InjectionDetector().detect(a)
    assert any(f.severity.name == "CRITICAL" for f in result.findings)


def test_signatures_catches_mimikatz():
    from recon.detectors.signatures import SignaturesDetector
    a = make_analysis(strings=["mimikatz.exe loaded"])
    result = SignaturesDetector().detect(a)
    assert any(f.severity.name == "CRITICAL" for f in result.findings)


def test_packer_high_entropy_section():
    from recon.core.core_wrapper import Section
    from recon.detectors.packer import PackerDetector
    a = make_analysis(sections=[
        Section(name=".text", address=0x1000, size=5000,
                raw_offset=0x1000, flags="X", entropy=7.85),
    ])
    result = PackerDetector().detect(a)
    assert any(f.name == "high_entropy_code" for f in result.findings)


def test_risk_calculator_caps_at_100():
    from recon.core.risk import RiskCalculator
    from recon.detectors.base_detector import DetectorResult, Finding, Severity

    # Создаём 20 CRITICAL findings — суммарно 500 баллов
    drs = [DetectorResult(detector="Test", findings=[
        Finding(detector="Test", name="x", description="x",
                severity=Severity.CRITICAL)
        for _ in range(20)
    ])]
    assessment = RiskCalculator().calculate(drs)
    assert assessment.score == 100  # capped
    assert assessment.level.value == "CRITICAL"
