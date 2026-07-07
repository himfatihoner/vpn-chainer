"""Post-up anonymity / leak-test suite.

Runs the same checks `verify_chain.sh` performs (minus the destructive
kill-test) but inline at the end of `up`, so the user gets a single
verdict on whether the chain is safe to use without having to invoke a
separate command.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
from dataclasses import dataclass

from . import host as host_mod
from . import netns as netns_mod
from . import util
from .detect import HopConfig

_TS_RE = re.compile(r"^\d{2}:\d{2}:\d{2}")


@dataclass
class Report:
    passed: int = 0
    failed: int = 0
    warned: int = 0

    @property
    def all_passed(self) -> bool:
        return self.failed == 0


def run_anonymity_check(
    topo: netns_mod.ChainTopology,
    configs: list[HopConfig],
    host_state: host_mod.HostState | None,
    *,
    sniff_seconds: int = 8,
) -> Report:
    """Run every non-destructive verification step and report colourfully.

    Returns a `Report`; caller can decide whether `up` should still be
    considered successful when warnings are present.
    """
    rep = Report()
    util.header("Post-up anonymity verification")

    _check_lockdown(topo, rep)
    _check_routing_loop(topo, rep)
    _check_masquerade_counters(topo, rep)
    _check_per_hop_exit_ips(topo, rep)
    if host_state is not None and host_state.redirect_done:
        _check_iptables_drop_rules(host_state, configs, rep)
        _check_wire_isolation(host_state, configs, rep, sniff_seconds=sniff_seconds)
    else:
        util.subheader("Wire isolation")
        util.step_warn("host default route not redirected (--no-redirect); skipping wire-isolation tests")
        rep.warned += 1

    _print_summary(rep)
    return rep


# ─────────────────────────── individual checks ───────────────────────────


def _check_lockdown(topo: netns_mod.ChainTopology, rep: Report) -> None:
    util.subheader("Lockdown firewall (default-DROP in every namespace)")
    for k in range(1, topo.n_hops + 1):
        ns = topo.ns(k)
        proc = util.run_in_ns(ns, ["iptables", "-S"], check=False)
        text = proc.stdout or ""
        wants = ("-P INPUT DROP", "-P OUTPUT DROP", "-P FORWARD DROP")
        if all(w in text for w in wants):
            util.step_ok(f"{ns}: INPUT/OUTPUT/FORWARD = DROP")
            rep.passed += 1
        else:
            missing = [w for w in wants if w not in text]
            util.step_fail(f"{ns}: missing policies → {', '.join(missing)}")
            rep.failed += 1


def _check_routing_loop(topo: netns_mod.ChainTopology, rep: Report) -> None:
    util.subheader("Routing closed-loop (1.1.1.1 must exit via the tunnel)")
    for k in range(1, topo.n_hops + 1):
        ns = topo.ns(k)
        proc = util.run_in_ns(ns, ["ip", "-4", "route", "get", "1.1.1.1"], check=False)
        first = (proc.stdout or "").strip().splitlines()[0] if proc.stdout else ""
        m = re.search(r"\bdev\s+(\S+)", first)
        iface = m.group(1) if m else "(none)"
        if iface.startswith("wgc") or iface.startswith("tun"):
            util.step_ok(f"{ns}: 1.1.1.1 → {util.C.GREEN}{iface}{util.C.RESET}")
            rep.passed += 1
        else:
            util.step_fail(f"{ns}: 1.1.1.1 → {util.C.RED}{iface}{util.C.RESET} "
                           f"(should be tunnel iface)")
            rep.failed += 1


def _check_masquerade_counters(topo: netns_mod.ChainTopology, rep: Report) -> None:
    util.subheader("MASQUERADE counters (NAT actually moving packets)")
    for k in range(1, topo.n_hops + 1):
        ns = topo.ns(k)
        proc = util.run_in_ns(
            ns, ["iptables", "-t", "nat", "-L", "POSTROUTING", "-nvx"],
            check=False,
        )
        line = next(
            (l for l in (proc.stdout or "").splitlines() if "MASQUERADE" in l),
            "",
        )
        m = re.match(r"\s*(\d+)\s+(\d+)\s+", line)
        pkts = int(m.group(1)) if m else 0
        if pkts > 0:
            util.step_ok(f"{ns}: {pkts} packets MASQUERADE'd")
            rep.passed += 1
        elif m:
            util.step_warn(f"{ns}: rule present, 0 packets so far (chain idle?)")
            rep.warned += 1
        else:
            util.step_fail(f"{ns}: MASQUERADE rule missing")
            rep.failed += 1


def _check_per_hop_exit_ips(topo: netns_mod.ChainTopology, rep: Report) -> None:
    util.subheader("Per-hop exit IPs (each hop should resolve to its own VPN exit)")
    if not shutil.which("curl"):
        util.step_warn("curl not installed — skipping exit-IP probes")
        rep.warned += 1
        return
    seen: list[str] = []
    for k in range(1, topo.n_hops + 1):
        ns = topo.ns(k)
        proc = util.run_in_ns(
            ns,
            ["curl", "-fsS", "--max-time", "10", "https://api.ipify.org"],
            check=False,
        )
        ip = (proc.stdout or "").strip()
        if not ip:
            util.step_fail(f"{ns}: exit IP probe failed")
            rep.failed += 1
            continue
        if ip in seen:
            util.step_fail(f"{ns}: {ip} (DUPLICATE — chain collapsing)")
            rep.failed += 1
        else:
            util.step_ok(f"{ns}: {util.C.CYAN}{ip}{util.C.RESET}")
            rep.passed += 1
        seen.append(ip)


def _check_iptables_drop_rules(
    host_state: host_mod.HostState,
    configs: list[HopConfig],
    rep: Report,
) -> None:
    util.subheader("Host iptables DROP rules for hops 2..N")
    if len(configs) < 2:
        util.step_info("only one hop, no anti-leak DROPs to verify")
        return
    for k in range(2, len(configs) + 1):
        ip = configs[k - 1].server_ip
        nic = host_state.orig_default_iface
        out_ok = util.run(
            ["iptables", "-C", "OUTPUT", "-d", ip, "-o", nic, "-j", "DROP"],
            check=False,
        ).returncode == 0
        fwd_ok = util.run(
            ["iptables", "-C", "FORWARD", "-d", ip, "-o", nic, "-j", "DROP"],
            check=False,
        ).returncode == 0
        if out_ok and fwd_ok:
            util.step_ok(f"hop {k}: -d {ip} -o {nic} -j DROP active in OUTPUT and FORWARD")
            rep.passed += 1
        else:
            util.step_fail(f"hop {k}: DROP rule missing "
                           f"(OUTPUT={out_ok}, FORWARD={fwd_ok})")
            rep.failed += 1


def _check_wire_isolation(
    host_state: host_mod.HostState,
    configs: list[HopConfig],
    rep: Report,
    *,
    sniff_seconds: int,
) -> None:
    util.subheader(
        f"Wire isolation — sniff {host_state.orig_default_iface} "
        f"for {sniff_seconds}s, only hop 1 should appear"
    )
    if not shutil.which("tcpdump"):
        util.step_warn("tcpdump not installed — skipping wire-isolation test")
        rep.warned += 1
        return
    nic = host_state.orig_default_iface
    hop1_ip = configs[0].server_ip

    util.step_info(f"generating chain traffic and sniffing… ({sniff_seconds}s window)")

    stop_evt = threading.Event()
    gen_thread = threading.Thread(target=_traffic_generator, args=(stop_evt,), daemon=True)
    gen_thread.start()
    try:
        # Positive control: hop 1 must be visible.
        seen = _sniff_for_ip(nic, hop1_ip, seconds=sniff_seconds)
        if seen > 0:
            util.step_ok(
                f"hop 1 ({hop1_ip}) on {nic}: traffic seen "
                f"{util.C.DIM}(positive control){util.C.RESET}"
            )
            rep.passed += 1
        else:
            util.step_warn(
                f"hop 1 ({hop1_ip}) on {nic}: NO traffic seen — chain may be idle, "
                f"results below are inconclusive"
            )
            rep.warned += 1

        # Negative tests: no hop K (K>=2) traffic on the wire.
        for k in range(2, len(configs) + 1):
            ip = configs[k - 1].server_ip
            seen = _sniff_for_ip(nic, ip, seconds=sniff_seconds)
            if seen == 0:
                util.step_ok(
                    f"hop {k} ({ip}): {util.C.GREEN}no direct traffic{util.C.RESET} "
                    f"on {nic} ({sniff_seconds}s window)"
                )
                rep.passed += 1
            else:
                util.step_fail(
                    f"hop {k} ({ip}): {util.C.RED}LEAK — {seen} packets{util.C.RESET} "
                    f"on {nic} (anonymity broken)"
                )
                rep.failed += 1
    finally:
        stop_evt.set()
        gen_thread.join(timeout=2)


# ─────────────────────────── traffic + sniff helpers ───────────────────────────


def _traffic_generator(stop: threading.Event) -> None:
    """Push some HTTPS traffic through the chain so the sniffer has something
    to match against. Runs until `stop` is set."""
    while not stop.is_set():
        try:
            subprocess.run(
                ["curl", "-s", "--max-time", "4", "-o", "/dev/null",
                 "https://api.ipify.org"],
                check=False, timeout=5,
            )
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        if stop.wait(1.0):
            break


def _sniff_for_ip(nic: str, target_ip: str, *, seconds: int) -> int:
    """Run tcpdump for at most `seconds`, return number of packets seen."""
    argv = [
        "timeout", str(seconds),
        "tcpdump", "-ni", nic,
        "-c", "1", "-n", "-q",
        f"host {target_ip}",
    ]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, check=False,
            timeout=seconds + 3,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 0
    out = proc.stdout or ""
    return sum(1 for line in out.splitlines() if _TS_RE.match(line))


# ─────────────────────────── summary ───────────────────────────


def _print_summary(rep: Report) -> None:
    util.header("Verdict")
    if rep.failed == 0 and rep.warned == 0:
        util.step_ok(f"{util.C.BOLD}all checks passed{util.C.RESET} — chain is safe to use")
    elif rep.failed == 0:
        util.step_warn(
            f"{rep.warned} warning(s); the chain is operational but not all checks "
            f"could be confirmed"
        )
    else:
        util.step_fail(
            f"{util.C.BOLD}{rep.failed} check(s) failed{util.C.RESET} — "
            f"do NOT trust the chain for anonymity. Run "
            f"{util.C.BOLD}./vpn_chainer.py down{util.C.RESET} and inspect logs."
        )

    print(f"  {util.badge(f'{rep.passed} passed', 'ok')}   "
          f"{util.badge(f'{rep.warned} warn', 'warn')}   "
          f"{util.badge(f'{rep.failed} failed', 'fail')}")
