"""Tiny ANSI helpers for readable demo / CLI output (no third-party deps)."""

import os
import sys

_ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
if os.name == "nt":  # enable ANSI escapes on Windows 10+ terminals
    os.system("")


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _ENABLED else text


def green(t: str) -> str:
    return _c("1;32", t)


def red(t: str) -> str:
    return _c("1;31", t)


def yellow(t: str) -> str:
    return _c("1;33", t)


def cyan(t: str) -> str:
    return _c("1;36", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def banner(title: str) -> None:
    line = "=" * 78
    print("\n" + cyan(line))
    print(cyan(f"  {title}"))
    print(cyan(line))


def status(ok: bool, text: str) -> str:
    return green(f"[PASS] {text}") if ok else red(f"[FAIL] {text}")
