#!/usr/bin/env python3
"""vpn-chainer — chain N WireGuard/OpenVPN tunnels via Linux netns + NAT.

Subcommands:
    up        Build the chain and exit (chain stays running in the background).
    down      Tear down a chain that was previously brought up.
    status    Show whether a chain is currently active and what it changed.
    recover   Force-cleanup any leftover state (post-reboot, post-kill -9).

State persists across script invocations and across reboots, so 'down' and
'recover' can always undo whatever 'up' configured — even if the kernel
namespaces have been blown away in the meantime.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
from pathlib import Path

from chainer import chain as chain_mod
from chainer import state as state_mod
from chainer import util
from chainer.detect import DetectError, HopConfig, detect


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    util.set_verbose(getattr(args, "verbose", False))

    if args.command is None:
        parser.print_help()
        return 2

    # status is read-only and useful without sudo; everything else needs root.
    if args.command != "status" and os.geteuid() != 0:
        util.err("must be run as root (sudo) — needs ip netns / iptables / sysctl")
        return 2

    if args.command == "up":
        return _cmd_up(args)
    if args.command == "down":
        return _cmd_down(args)
    if args.command == "status":
        return _cmd_status(args)
    if args.command == "recover":
        return _cmd_recover(args)
    parser.print_help()
    return 2


# ─────────────────────────── argparse ───────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vpn_chainer",
        description="Chain multiple WireGuard/OpenVPN tunnels using Linux "
                    "network namespaces + NAT, applied to the whole host.",
    )
    sub = p.add_subparsers(dest="command", required=False)

    pu = sub.add_parser("up", help="bring up a chain (script exits when ready)")
    pu.add_argument("-n", "--hops", type=int,
                    help="Number of hops (1-8). Prompted if omitted.")
    pu.add_argument("-c", "--config", action="append", default=[],
                    metavar="PATH",
                    help="VPN config path. Repeat per hop, outer→inner.")
    pu.add_argument("--type", action="append", default=[], dest="types",
                    choices=["wg", "ovpn"],
                    help="Force VPN type per hop (parallel to --config).")
    pu.add_argument("--no-redirect", action="store_true",
                    help="Don't change the host default route.")
    pu.add_argument("--keep-host-dns", action="store_true",
                    help="Leave /etc/resolv.conf alone (may leak DNS).")
    pu.add_argument("--chain-dns", default="1.1.1.1",
                    help="DNS server to use through the chain. Default: 1.1.1.1.")
    pu.add_argument("-y", "--yes", action="store_true",
                    help="Skip the 'Proceed?' confirmation.")
    pu.add_argument("-v", "--verbose", action="store_true",
                    help="Echo every shell command.")

    pd = sub.add_parser("down", help="tear down the running chain")
    pd.add_argument("-v", "--verbose", action="store_true")

    ps = sub.add_parser("status", help="show current chain state")
    ps.add_argument("--json", action="store_true",
                    help="Emit machine-readable JSON instead of a text table.")
    ps.add_argument("-v", "--verbose", action="store_true")

    pr = sub.add_parser("recover",
                        help="force-clean leftover state (post-reboot or kill -9)")
    pr.add_argument("-y", "--yes", action="store_true",
                    help="Skip the confirmation prompt.")
    pr.add_argument("-v", "--verbose", action="store_true")

    return p


# ─────────────────────────── up ───────────────────────────


def _cmd_up(args: argparse.Namespace) -> int:
    if state_mod.state_present():
        util.err(
            "a chain is already configured (state files present in "
            f"{util.PERSIST_DIR}). Run 'sudo {sys.argv[0]} down' first, or "
            f"'sudo {sys.argv[0]} recover' if it's stale."
        )
        return 1

    try:
        configs = _gather_configs(args)
    except (DetectError, FileNotFoundError, ValueError) as e:
        util.err(str(e))
        return 1

    if not _check_required_tools(configs):
        return 1

    util.banner("bringing the chain up")
    util.header(f"Chain plan ({len(configs)} hops, outer → inner)")
    print(f"  {util.chain_flow(len(configs))}\n")
    print(util.chain_orbit(len(configs), server_ips=[c.server_ip for c in configs]))
    print()
    for k, c in enumerate(configs, 1):
        kind_col = util.C.MAGENTA if c.kind == "wireguard" else util.C.BLUE
        creds = (f"  {util.badge('needs credentials', 'warn')}"
                 if c.needs_credentials else "")
        print(f"  {util.C.BOLD}{k}{util.C.RESET}. "
              f"{kind_col}{c.kind:<9}{util.C.RESET} "
              f"{util.C.CYAN}{c.server_host}:{c.server_port}{util.C.RESET} "
              f"{util.C.DIM}({c.server_ip}){util.C.RESET}  "
              f"{util.C.DIM}{c.path}{util.C.RESET}{creds}")

    if not args.yes and not _confirm("Proceed?"):
        util.log("aborted")
        return 0

    try:
        chain_mod.build_chain(
            configs,
            redirect_host=not args.no_redirect,
            keep_host_dns=args.keep_host_dns,
            chain_dns=args.chain_dns,
        )
    except util.CmdError as e:
        util.err(str(e))
        return 1
    except Exception as e:
        util.err(f"unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    util.header("Done")
    util.step_ok(f"{util.C.BOLD}chain is up{util.C.RESET}")
    util.step_info(f"{util.C.DIM}sudo {sys.argv[0]} status{util.C.RESET}  "
                   f"— inspect current state")
    util.step_info(f"{util.C.DIM}sudo {sys.argv[0]} down{util.C.RESET}    "
                   f"— tear down and restore")
    util.step_info(f"{util.C.DIM}sudo ./verify_chain.sh{util.C.RESET}     "
                   f"— full external verification")
    return 0


# ─────────────────────────── down ───────────────────────────


def _cmd_down(args: argparse.Namespace) -> int:
    util.banner("tearing the chain down")
    if not state_mod.state_present():
        util.step_warn("no chain state on disk — nothing to do")
        return 0
    try:
        chain_mod.teardown_chain()
    except Exception as e:
        util.err(f"teardown failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        util.err(f"try {util.C.BOLD}sudo {sys.argv[0]} recover{util.C.RESET} to force-clean")
        return 1
    util.step_ok(f"{util.C.BOLD}chain torn down{util.C.RESET}; host restored to "
                 f"its original network configuration")
    return 0


# ─────────────────────────── status ───────────────────────────


def _cmd_status(args: argparse.Namespace) -> int:
    info = chain_mod.chain_status()
    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    if not info["present"]:
        util.banner("status")
        util.kv("chain", util.badge("NOT ACTIVE", "dim") + "  (no state on disk)")
        return 0

    alive = info["alive"]
    badge_text = util.badge("ACTIVE", "ok") if alive else util.badge("STALE", "fail")
    badge_note = "" if alive else "  (kernel state missing — needs recover)"

    util.banner("status")
    util.kv("chain", f"{badge_text}{badge_note}")
    util.kv("started", info["started_at"] or "-")
    util.kv("hops", f"{info['n_hops']}  "
                    f"{util.C.DIM}({', '.join(info['namespaces'])}){util.C.RESET}")
    util.kv("redirect",
            util.badge("host default → ingress veth", "ok") if info["redirect_done"]
            else util.badge("host untouched", "dim"))
    if info["host_orig_default"]:
        util.kv("orig default", info["host_orig_default"])

    util.header("Topology")
    print(f"  {util.chain_flow(info['n_hops'])}\n")
    server_ips = [h.get("server_ip", "") for h in info["hops"]]
    print(util.chain_orbit(info["n_hops"], server_ips=server_ips))
    print()

    util.header("Hops")
    print(f"  {util.C.BOLD}{'#':<3}{'kind':<11}{'iface':<10}{'pid':<10}config{util.C.RESET}")
    for h in info["hops"]:
        kind_col = util.C.MAGENTA if h["kind"] == "wireguard" else util.C.BLUE
        if h["ovpn_pid"]:
            pid_disp = (f"{h['ovpn_pid']}" if h["ovpn_alive"]
                        else f"{util.C.RED}{h['ovpn_pid']} (dead){util.C.RESET}")
        else:
            pid_disp = util.C.DIM + "-" + util.C.RESET
        print(f"  {h['k']:<3}{kind_col}{h['kind']:<11}{util.C.RESET}"
              f"{util.C.CYAN}{h['iface']:<10}{util.C.RESET}"
              f"{pid_disp:<10}"
              f"{util.C.DIM}{h['config']}{util.C.RESET}")

    if not alive:
        print()
        util.warn(f"kernel namespaces are gone — "
                  f"run {util.C.BOLD}sudo {sys.argv[0]} recover{util.C.RESET}")
    return 0 if alive else 1


# ─────────────────────────── recover ───────────────────────────


def _cmd_recover(args: argparse.Namespace) -> int:
    util.banner("recovery mode")
    if not args.yes:
        util.subheader("This will:")
        util.step_info("stop any leftover vpnchain_* OpenVPN processes")
        util.step_info("delete every vpnchain_* namespace and vpnc* veth")
        util.step_info("undo host iptables rules (MASQUERADE swept by pattern even with no state file)")
        util.step_info("rebuild the host default route and restore /etc/resolv.conf")
        util.step_info("wipe all state under /var/lib/vpnchainer/ and /run/vpnchainer/")
        if not _confirm("Continue?"):
            util.log("aborted")
            return 0
    try:
        chain_mod.recover()
    except Exception as e:
        util.err(f"recover failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    util.step_ok(f"{util.C.BOLD}recovery complete{util.C.RESET}")
    return 0


# ─────────────────────────── shared helpers ───────────────────────────


def _gather_configs(args: argparse.Namespace) -> list[HopConfig]:
    if args.hops is not None:
        n_hops = args.hops
    elif args.config:
        n_hops = len(args.config)
    else:
        n_hops = _prompt_int("How many VPNs do you want to chain? (1-8)", 1, 8)

    if n_hops < 1 or n_hops > 8:
        raise ValueError("hops must be between 1 and 8")

    paths: list[str] = list(args.config)
    while len(paths) < n_hops:
        idx = len(paths) + 1
        path = input(f"  Hop {idx} config path: ").strip()
        if not path:
            raise ValueError("empty path")
        paths.append(path)

    types: list[str | None] = [
        ({"wg": "wireguard", "ovpn": "openvpn"}.get(t)) for t in args.types
    ]
    while len(types) < n_hops:
        types.append(None)

    out: list[HopConfig] = []
    for i, raw in enumerate(paths[:n_hops]):
        path = Path(os.path.expanduser(raw)).resolve()
        cfg = detect(path, override=types[i])  # type: ignore[arg-type]
        suffix = " [needs credentials]" if cfg.needs_credentials else ""
        print(f"    -> {path.name}: detected {cfg.kind} "
              f"({cfg.server_host}:{cfg.server_port} → {cfg.server_ip}){suffix}")
        out.append(cfg)

    _prompt_credentials(out)
    return out


def _prompt_credentials(configs: list[HopConfig]) -> None:
    for k, cfg in enumerate(configs, 1):
        if not cfg.needs_credentials:
            continue
        print(f"\n  hop {k} ({cfg.path.name}) requires VPN credentials:")
        username = input(f"    username for {cfg.server_host}: ").strip()
        if not username:
            raise ValueError(f"hop {k}: empty username")
        password = getpass.getpass(f"    password for {cfg.server_host}: ")
        if not password:
            raise ValueError(f"hop {k}: empty password")
        cfg.username = username
        cfg.password = password


def _check_required_tools(configs: list[HopConfig]) -> bool:
    needs_wg = any(c.kind == "wireguard" for c in configs)
    needs_ovpn = any(c.kind == "openvpn" for c in configs)
    missing: list[str] = []
    if needs_wg and not shutil.which("wg"):
        missing.append("wg (wireguard-tools)")
    if needs_ovpn and not shutil.which("openvpn"):
        missing.append("openvpn")
    for tool in ("ip", "iptables", "sysctl"):
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        util.err("missing required tools: " + ", ".join(missing))
        if "wg (wireguard-tools)" in missing:
            util.err("  install with: sudo apt install wireguard-tools")
        return False
    return True


def _prompt_int(prompt: str, lo: int, hi: int) -> int:
    while True:
        raw = input(f"{prompt} ").strip()
        try:
            v = int(raw)
        except ValueError:
            print(f"  invalid number: {raw!r}")
            continue
        if v < lo or v > hi:
            print(f"  must be between {lo} and {hi}")
            continue
        return v


def _confirm(prompt: str) -> bool:
    raw = input(f"{prompt} [y/N] ").strip().lower()
    return raw in ("y", "yes")


if __name__ == "__main__":
    sys.exit(main())
