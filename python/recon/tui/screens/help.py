"""
HelpScreen — экран справки.

Содержит:
  - Описание программы и её версии
  - Таблицу горячих клавиш
  - Описание 7 детекторов
  - Ссылки на документацию

Это статический экран — не имеет интерактивных элементов, кроме
"Back" по Esc и "Quit" из глобальных биндингов.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from recon import __version__


_HELP_TEXT = f"""\
[b]Binary Recon[/b]  v{__version__}

Static analysis tool for ELF (Linux) and PE (Windows) executables.
Examines a binary without running it, extracting structural data
and looking for suspicious behavioural patterns.

[b]GLOBAL KEY BINDINGS[/b]

  Ctrl+Q          Quit application
  ?  or  F1       Show this help screen
  Esc             Go back to previous screen

[b]WELCOME SCREEN[/b]

  A               Analyze a single file
  B               Batch scan a directory
  H               Browse scan history

[b]DETECTORS[/b]

  AntiDebug    — IsDebuggerPresent, ptrace, debugger references
  Network      — sockets, HTTP APIs, hardcoded URLs/IPs
  Packer       — UPX/Themida signatures, high-entropy sections
  Persistence  — registry autostart, services, cron, systemd
  Injection    — VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
  Crypto       — CryptoAPI, BCrypt, OpenSSL, algorithm signatures
  Signatures   — known malware names, suspicious commands, double extensions

[b]RISK LEVELS[/b]

  CLEAN     0 points     no suspicious indicators
  LOW       1-19         minor indicators, often false positives
  MEDIUM    20-39        several indicators, deserves attention
  HIGH      40-69        combination of serious indicators
  CRITICAL  70-100       almost certainly malware

[b]OUTPUT MODES[/b]

  CLI offers three output modes:
    recon <file>           pretty human-readable
    recon <file> --json    structured JSON for pipelines
    recon <file> -q        one-line summary

[b]LINKS[/b]

  Documentation:  ./docs/
  Source code:    https://github.com/Klimov-Ilya-bauman/binary-recon
  License:        MIT
"""


class HelpScreen(Screen):
    """Экран справки. Прокручиваемый, чтобы влезало много текста."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back", show=True),
        Binding("q",      "app.pop_screen", "Back", show=False),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="help-scroll"):
            with Vertical(id="help-content"):
                # markup=True позволяет использовать BBCode-теги [b], [i] и т.п.
                yield Static(_HELP_TEXT, id="help-text", markup=True)
        yield Footer()
