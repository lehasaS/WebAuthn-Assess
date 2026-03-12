from __future__ import annotations

import os
import sys
from typing import TextIO


_FG_CODES = {
    "black": "30",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
}


def resolve_color_enabled(mode: str = "auto", stream: TextIO | None = None) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.getenv("NO_COLOR"):
        return False
    out = stream or sys.stdout
    return bool(getattr(out, "isatty", lambda: False)())


def colorize(
    text: str,
    *,
    fg: str | None = None,
    bold: bool = False,
    dim: bool = False,
    enabled: bool = True,
) -> str:
    if not enabled:
        return text
    codes: list[str] = []
    if bold:
        codes.append("1")
    if dim:
        codes.append("2")
    if fg:
        code = _FG_CODES.get(fg)
        if code:
            codes.append(code)
    if not codes:
        return text
    start = "\033[" + ";".join(codes) + "m"
    return f"{start}{text}\033[0m"

