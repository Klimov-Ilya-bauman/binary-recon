# Binary Recon

> Static analysis tool for ELF and PE executables with interactive terminal interface

[![CI](https://github.com/Klimov-Ilya-bauman/binary-recon/actions/workflows/ci.yml/badge.svg)](https://github.com/Klimov-Ilya-bauman/binary-recon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-green.svg)

Binary Recon parses ELF (Linux) and PE (Windows) executables **without running them**, extracts structural data, and runs seven detectors to produce a **Risk Score from 0 to 100**.

## Demo
$ recon tests/samples/windows/hello.exe
=== Binary Recon Analysis ===
File:     /home/user/hello.exe
Format:   PE (x86_64, 64-bit)
Size:     50,176 bytes
MD5:      a3b1c2...
SHA256:   8f4d2e...
Entropy:  6.0412
Risk:     18/100 — LOW
Summary:  1 finding across 7 detectors
Findings (1):
[HIGH    ] AntiDebug: Windows anti-debug API import: IsDebuggerPresent
evidence: IsDebuggerPresent

## Features

- **ELF parser** — sections, imports (dynamic symbol table), strings, per-section entropy
- **PE parser** — DOS + COFF + Optional Headers, Import Directory walking
- **Hashes** — MD5 and SHA-256 implemented from RFC 1321 / FIPS 180-4 (no OpenSSL)
- **Shannon entropy** — file-level and per-section, detects packed code
- **Seven detectors** — AntiDebug, Network, Packer, Persistence, Injection, Crypto, Signatures
- **Three interfaces** — CLI, batch CLI, interactive TUI (Textual)
- **SQLite history** — every scan auto-saved, searchable, filterable
- **Three export formats** — JSON for pipelines, HTML for sharing, Markdown for issues

## Architecture

Two-layer design: **C++ core** handles low-level parsing and cryptographic work; **Python layer** runs detectors, manages state, renders UI. Communication via `subprocess` + JSON contract.
Python (Analyzer + 7 detectors + RiskCalculator + TUI + SQLite + Export)
↕ subprocess + JSON (schema v1.0)
C++ core (FormatDetector + ELF/PE parsers + Hashes + Entropy)

See [docs/architecture.md](docs/architecture.md) for details.

## Quick Start

### From source

```bash
git clone https://github.com/Klimov-Ilya-bauman/binary-recon.git
cd binary-recon
make build
recon-tui                          # interactive TUI
recon /bin/ls                      # one-shot CLI
recon-batch /usr/bin               # scan a whole directory
```

### From a release archive

Download the latest `tar.gz` for your architecture from [Releases](https://github.com/Klimov-Ilya-bauman/binary-recon/releases), then:

```bash
tar xzf binary-recon-1.0.0-linux-arm64.tar.gz
cd binary-recon-1.0.0
./install.sh
```

## Requirements

- Linux (Ubuntu 22.04+, Debian 12+, Fedora 38+, or equivalent)
- GCC 9+ or Clang 10+ with C++17 support
- CMake 3.16+
- Python 3.9+
- A terminal with 256 colors and Unicode

## Usage

### CLI

```bash
recon <file>                        # human-readable output
recon <file> -q                     # one-line summary
recon <file> --json                 # JSON for scripts
recon <file> --export html -o out.html   # save HTML report
```

### Batch

```bash
recon-batch /usr/bin                # scan directory recursively
recon-batch /usr/bin --workers 8    # 8 parallel workers
```

### TUI

```bash
recon-tui                           # interactive interface
```

Key bindings: `A` analyze · `B` batch · `H` history · `?` help · `Ctrl+Q` quit

## Risk Levels

| Score   | Level    | Meaning                                          |
|---------|----------|--------------------------------------------------|
| 0       | CLEAN    | No suspicious indicators                         |
| 1–19    | LOW      | Minor indicators, often false positives          |
| 20–39   | MEDIUM   | Several indicators, deserves attention           |
| 40–69   | HIGH     | Combination of serious indicators                |
| 70–100  | CRITICAL | Almost certainly malware                         |

## Detectors

- **AntiDebug** — `IsDebuggerPresent`, `ptrace`, debugger string references
- **Network** — Winsock/HTTP APIs, hardcoded URLs/IPs (with benign-domain whitelist)
- **Packer** — UPX/Themida signatures, high-entropy code sections
- **Persistence** — registry autostart, Windows services, cron, systemd
- **Injection** — `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
- **Crypto** — CryptoAPI, BCrypt, OpenSSL, ransomware-style extensions
- **Signatures** — known malware names, suspicious commands, double extensions

## Documentation

- [Technical specification (GOST 19.201-78)](docs/TZ_GOST.docx)
- [User stories, UML, MoSCoW](docs/UserStories_UML_MoSCoW.docx)
- [C++ core documentation](docs/CPP_Core_Documentation.docx)
- [Architecture](docs/architecture.md)
- UML diagrams in [docs/uml/](docs/uml/)

## Development

```bash
make build         # build C++ core + install Python package
make test          # run all tests (C++ shell + pytest)
make lint          # ruff
make clean         # remove build artifacts
```

## License

MIT — see [LICENSE](LICENSE).
