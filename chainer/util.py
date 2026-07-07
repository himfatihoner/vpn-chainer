"""Shared subprocess + logging helpers (with TTY-aware ANSI colors)."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

VERBOSE = False

# Persistent state — survives reboots so we can still restore /etc/resolv.conf
# and roll back firewall changes even if the running session is lost.
PERSIST_DIR = Path("/var/lib/vpnchainer")
# Ephemeral state — log files, pid files, credentials. Recreated on every up.
RUN_DIR = Path("/run/vpnchainer")


# ─────────────────────────── coloring ───────────────────────────


class C:
    """ANSI escape sequences. Empty when stdout isn't a TTY (or NO_COLOR set)."""
    RESET = ""
    BOLD = ""
    DIM = ""
    ITALIC = ""
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    CYAN = ""
    MAGENTA = ""
    # Bright variants for the banner gradient.
    B_RED = ""
    B_GREEN = ""
    B_YELLOW = ""
    B_BLUE = ""
    B_CYAN = ""
    B_MAGENTA = ""


def _enable_colors() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("VPNCHAINER_FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def init_colors() -> None:
    if _enable_colors():
        C.RESET = "\033[0m"
        C.BOLD = "\033[1m"
        C.DIM = "\033[2m"
        C.ITALIC = "\033[3m"
        C.RED = "\033[31m"
        C.GREEN = "\033[32m"
        C.YELLOW = "\033[33m"
        C.BLUE = "\033[34m"
        C.CYAN = "\033[36m"
        C.MAGENTA = "\033[35m"
        C.B_RED = "\033[91m"
        C.B_GREEN = "\033[92m"
        C.B_YELLOW = "\033[93m"
        C.B_BLUE = "\033[94m"
        C.B_CYAN = "\033[96m"
        C.B_MAGENTA = "\033[95m"
    else:
        for k in ("RESET", "BOLD", "DIM", "ITALIC",
                  "RED", "GREEN", "YELLOW", "BLUE", "CYAN", "MAGENTA",
                  "B_RED", "B_GREEN", "B_YELLOW", "B_BLUE", "B_CYAN", "B_MAGENTA"):
            setattr(C, k, "")


init_colors()


def set_verbose(v: bool) -> None:
    global VERBOSE
    VERBOSE = v


# ─────────────────────────── log primitives ─────────────────────


def log(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.RESET} {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}", file=sys.stderr, flush=True)


def err(msg: str) -> None:
    print(f"{C.RED}[x]{C.RESET} {msg}", file=sys.stderr, flush=True)


def trace(msg: str) -> None:
    if VERBOSE:
        print(f"    {C.DIM}$ {msg}{C.RESET}", file=sys.stderr, flush=True)


# ─────────────────────────── pretty output ──────────────────────


def header(text: str) -> None:
    """Section banner. Bold cyan with full-width separator."""
    print()
    rule = "─" * max(0, 60 - len(text) - 4)
    print(f"{C.BOLD}{C.CYAN}── {text} {rule}{C.RESET}")


def subheader(text: str) -> None:
    """Smaller heading inside a section."""
    print(f"{C.BOLD}{text}{C.RESET}")


def step_ok(msg: str) -> None:
    print(f"  {C.GREEN}✓{C.RESET} {msg}", flush=True)


def step_fail(msg: str) -> None:
    print(f"  {C.RED}✗{C.RESET} {msg}", flush=True)


def step_warn(msg: str) -> None:
    print(f"  {C.YELLOW}!{C.RESET} {msg}", flush=True)


def step_info(msg: str) -> None:
    print(f"  {C.DIM}·{C.RESET} {msg}", flush=True)


def kv(label: str, value: str, *, value_color: str = "") -> None:
    """Aligned 'key : value' line for status-style readouts."""
    print(f"  {C.DIM}{label:<14}{C.RESET}{value_color}{value}{C.RESET}")


def badge(text: str, kind: str) -> str:
    """Inline coloured badge for status words like ACTIVE / STALE / FAIL."""
    palette = {
        "ok":   C.GREEN,
        "warn": C.YELLOW,
        "fail": C.RED,
        "info": C.CYAN,
        "dim":  C.DIM,
    }
    col = palette.get(kind, "")
    return f"{col}{C.BOLD}{text}{C.RESET}"


# Compact 4-row banner — fits "VPN Chainer" in ~52 cols.
_LOGO = [
    r"__   _____  _  _    ___ _         _              ",
    r"\ \ / / _ \| \| |  / __| |_  __ _(_)_ _  ___ _ _ ",
    r" \ V /|  _/| .` | | (__| ' \/ _` | | ' \/ -_) '_|",
    r"  \_/ |_|  |_|\_|  \___|_||_\__,_|_|_||_\___|_|  ",
]
# Cyan→magenta gradient over the 4 rows.
_LOGO_GRADIENT = ["B_CYAN", "CYAN", "B_MAGENTA", "MAGENTA"]


def banner(subtitle: str = "", *, version: str = "0.1.0") -> None:
    """ASCII-art project banner. `subtitle` describes the running command.

    Falls back to a single-line title when the terminal is narrow or non-TTY.
    """
    import shutil as _shutil
    width = _shutil.get_terminal_size((80, 24)).columns

    # Banner is ~52 cols wide. Fall back to the simple boxed title only on
    # genuinely narrow terminals (or when ANSI is disabled).
    if width < 56 or not _enable_colors():
        title = "vpn-chainer"
        if subtitle:
            title += f"  ·  {subtitle}"
        rule = "─" * (len(title) + 2)
        print()
        print(f"{C.BOLD}{C.CYAN}┌{rule}┐{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}│ {title} │{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}└{rule}┘{C.RESET}")
        print()
        return

    print()
    for i, line in enumerate(_LOGO):
        col = getattr(C, _LOGO_GRADIENT[i])
        print(f"  {C.BOLD}{col}{line}{C.RESET}")

    # Tagline lines under the banner.
    print()
    print(
        f"  {C.BOLD}{C.B_CYAN}╶╶ chain · builder ╶╶{C.RESET}   "
        f"{C.DIM}v{version} · netns + iptables lockdown{C.RESET}"
    )
    if subtitle:
        print(f"  {C.BOLD}{C.B_YELLOW}▶ {subtitle}{C.RESET}")
    print()


def chain_flow(hops: int, *, host_label: str = "host",
               exit_label: str = "internet") -> str:
    """ASCII flow showing host → hop1 → … → hopN → internet, coloured."""
    arrow = f"{C.DIM} ━━▶ {C.RESET}"
    parts = [f"{C.BOLD}{C.B_GREEN}[{host_label}]{C.RESET}"]
    palette = [C.B_CYAN, C.CYAN, C.B_MAGENTA, C.MAGENTA, C.B_BLUE, C.BLUE,
               C.B_YELLOW, C.YELLOW]
    for i in range(1, hops + 1):
        col = palette[(i - 1) % len(palette)]
        parts.append(f"{C.BOLD}{col}[hop{i}]{C.RESET}")
    parts.append(f"{C.BOLD}{C.B_YELLOW}[{exit_label}]{C.RESET}")
    return arrow.join(parts)


# ─────────────── chain_orbit (concentric onion visualization) ───────────────


import re as _re

_ANSI_RE = _re.compile(r"\033\[[0-9;]*m")


def _vlen(s: str) -> int:
    """Visible length of `s` (ANSI escape sequences stripped)."""
    return len(_ANSI_RE.sub("", s))


def _wrap_in_orbit(
    inner: list[str], label: str, *,
    color: str, pad_h: int = 2, badge: str = "",
) -> list[str]:
    """Wrap `inner` in a hexagonal orbital ring with tapered sides.

    Visual structure:
            ╭──── hop K ────╮      (top, corners inset by 2)
           ╱                 ╲     (taper, slashes inset by 1)
          │     <inner>       │    (middle, borders at edge)
           ╲                 ╱     (taper)
            ╰───────────────╯      (bottom)

    A small badge (e.g. an IP) can ride the bottom border:
            ╰──[ 1.2.3.4 ]───╯
    """
    inner_w = max((_vlen(s) for s in inner), default=0)
    label_text = f" {label} "
    badge_text = f"┤ {badge} ├" if badge else ""

    # Total ring width T must satisfy:
    #   middle row holds inner with horiz padding: T-2 ≥ inner_w + 2*pad_h
    #   top label line has at least one dash either side: T-6 ≥ len(label) + 2
    #   bottom badge (if any) needs T-6 ≥ len(badge_text) + 2
    T = max(
        inner_w + 2 * pad_h + 2,
        len(label_text) + 8,
        len(badge_text) + 8 if badge_text else 0,
    )

    middle_inner = T - 2
    slash_inner = T - 4
    top_corner_span = T - 6  # chars between ╭ and ╮ (label + dashes)

    label_dashes = top_corner_span - len(label_text)
    lab_l = label_dashes // 2
    lab_r = label_dashes - lab_l

    if badge_text:
        badge_dashes = top_corner_span - len(badge_text)
        bdg_l = badge_dashes // 2
        bdg_r = badge_dashes - bdg_l
        bottom_inner = (
            f"{'─' * bdg_l}{C.BOLD}{badge_text}{C.RESET}{color}{'─' * bdg_r}"
        )
    else:
        bottom_inner = "─" * top_corner_span

    side = f"{color}│{C.RESET}"
    top = (f"  {color}╭{'─' * lab_l}{C.BOLD}{label_text}{C.RESET}"
           f"{color}{'─' * lab_r}╮{C.RESET}  ")
    bottom = f"  {color}╰{bottom_inner}╯{C.RESET}  "
    taper_top = f" {color}╱{C.RESET}{' ' * slash_inner}{color}╲{C.RESET} "
    taper_bot = f" {color}╲{C.RESET}{' ' * slash_inner}{color}╱{C.RESET} "

    out: list[str] = [top, taper_top]
    for line in inner:
        vlen = _vlen(line)
        l = (middle_inner - vlen) // 2
        r = middle_inner - vlen - l
        out.append(f"{side}{' ' * l}{line}{' ' * r}{side}")
    out.append(taper_bot)
    out.append(bottom)
    return out


def chain_orbit(
    n_hops: int,
    *,
    indent: int = 1,
    server_ips: list[str] | None = None,
) -> str:
    """Concentric hexagonal-orbit visualization of the chain.

    Host sits at the centre. Each hop wraps it as a labelled ring with
    tapered sides — innermost ring is hop_N (last wrap applied), outermost
    is hop_1 (the carrier visible on the wire). If `server_ips` is provided,
    each ring shows that hop's server IP as a badge on the bottom border.
    A stylised exit channel points out to the internet.
    """
    if n_hops < 1:
        return ""

    palette = [
        C.B_MAGENTA, C.MAGENTA,
        C.B_BLUE, C.BLUE,
        C.B_CYAN, C.CYAN,
        C.B_YELLOW, C.YELLOW,
    ]

    centre = (
        f"{C.BOLD}{C.B_GREEN}● host{C.RESET}"
    )
    block: list[str] = [centre]

    for k in range(n_hops, 0, -1):
        col = palette[(k - 1) % len(palette)]
        ip = server_ips[k - 1] if server_ips and k <= len(server_ips) else ""
        block = _wrap_in_orbit(block, f"hop {k}", color=col, badge=ip)

    width = max(_vlen(line) for line in block)
    centre_col = width // 2
    pad = " " * indent

    # Output channel — a stylised "antenna" at the bottom that suggests packets
    # leaving the outermost shell into the wire.
    arrow_lines = [
        f"{C.DIM}┊{C.RESET}",
        f"{C.DIM}┊{C.RESET}",
        f"{C.DIM}━┯━{C.RESET}",
        f"{C.B_YELLOW}{C.BOLD}▼{C.RESET}",
    ]
    arrow_visible_widths = [1, 1, 3, 1]

    out_lines = [pad + line for line in block]
    out_lines.append("")
    for line, vw in zip(arrow_lines, arrow_visible_widths):
        col_off = max(0, centre_col - vw // 2)
        out_lines.append(pad + " " * col_off + line)

    label = f"{C.BOLD}{C.B_YELLOW}🌐  internet  ⟶{C.RESET}"
    label_w = _vlen(label)
    out_lines.append(
        pad + " " * max(0, centre_col - label_w // 2) + label
    )

    return "\n".join(out_lines)


# ─────────────────────────── subprocess ─────────────────────────


class CmdError(RuntimeError):
    def __init__(self, argv: Sequence[str], rc: int, stderr: str):
        self.argv = list(argv)
        self.rc = rc
        self.stderr = stderr
        super().__init__(
            f"command failed (rc={rc}): {shlex.join(argv)}\n{stderr.strip()}"
        )


def run(
    argv: Sequence[str] | str,
    *,
    check: bool = True,
    capture: bool = True,
    input_text: str | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command. argv may be a list or a shell-style string."""
    if isinstance(argv, str):
        argv_list = shlex.split(argv)
    else:
        argv_list = list(argv)
    trace(shlex.join(argv_list))
    full_env = None
    if env is not None:
        full_env = os.environ.copy()
        full_env.update(env)
    proc = subprocess.run(
        argv_list,
        capture_output=capture,
        text=True,
        input=input_text,
        timeout=timeout,
        check=False,
        env=full_env,
    )
    if check and proc.returncode != 0:
        raise CmdError(argv_list, proc.returncode, proc.stderr or "")
    return proc


def run_in_ns(ns: str, argv: Sequence[str] | str, **kw) -> subprocess.CompletedProcess[str]:
    if isinstance(argv, str):
        argv = shlex.split(argv)
    return run(["ip", "netns", "exec", ns, *argv], **kw)
