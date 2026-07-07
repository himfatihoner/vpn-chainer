"""Connectivity checks: per-hop exit IP probe + final whole-host traceroute."""

from __future__ import annotations

import shutil

from . import netns as netns_mod
from .util import log, run, run_in_ns, warn

EXIT_PROBE_URLS = ["https://api.ipify.org", "https://ifconfig.me/ip"]


def probe_exit_ip(ns: str, *, timeout_s: int = 12) -> str | None:
    """Return public IP as seen from inside `ns`, or None on failure."""
    if not shutil.which("curl"):
        warn("curl not found; skipping exit-IP probe")
        return None
    for url in EXIT_PROBE_URLS:
        proc = run_in_ns(
            ns,
            ["curl", "-fsSL", "--max-time", str(timeout_s), url],
            check=False,
        )
        if proc.returncode == 0:
            ip = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout else ""
            if ip:
                return ip
    return None


def final_traceroute(target: str = "1.1.1.1", *, max_hops: int = 12) -> None:
    """Run traceroute from the host (i.e. through the whole chain) and pretty-print."""
    if not shutil.which("traceroute"):
        warn("traceroute not installed (apt install traceroute) — skipping final test")
        return
    log(f"traceroute to {target} (host → chain → internet):")
    proc = run(
        ["traceroute", "-n", "-q", "1", "-w", "2",
         "-m", str(max_hops), target],
        check=False,
    )
    out = proc.stdout or ""
    for line in out.splitlines():
        print(f"    {line}")
    if proc.returncode != 0:
        warn("traceroute returned non-zero — chain may be incomplete")


def whole_chain_summary(topo: netns_mod.ChainTopology, exit_ips: list[str | None]) -> None:
    log("chain summary:")
    for k, ns in enumerate(topo.namespaces, 1):
        ip = exit_ips[k - 1] or "unknown"
        print(f"    hop {k}: {ns} → public IP {ip}")
