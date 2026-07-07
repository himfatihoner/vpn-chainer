"""Host-side network plumbing — applied in two phases.

Phase 1: `enable_chain_forwarding`
  Run BEFORE bringing up any VPN. Enables ip_forward and SNAT for the chain
  subnets out the host's physical NIC, so traffic from the namespaces can reach
  the public internet via the host's *existing* default route. Without this,
  VPN_1's encrypted carrier from ns_1 would be black-holed at the host.

Phase 2: `redirect_default_route`
  Run AFTER all VPNs are up. Pins VPN_1's endpoint IP to the original gateway
  (so the carrier still routes correctly when the default changes) and replaces
  the host's default route with the veth into ns_1. Also swaps /etc/resolv.conf
  so DNS goes through the chain.

Teardown is `restore` (idempotent, undoes both phases).
"""

from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from . import netns as netns_mod
from .util import PERSIST_DIR, log, run, warn

STATE_FILE = PERSIST_DIR / "host_state.json"
RESOLV_PATH = Path("/etc/resolv.conf")

# Base /16 prefixes the chain subnets may use (see netns.DEFAULT_BASE_PREFIX /
# FALLBACK_PREFIXES). The heuristic sweep uses these to recognise a leftover
# chain MASQUERADE rule when host_state.json is gone.
_CHAIN_PREFIXES = ("10.200.0.0/16", "10.201.0.0/16", "10.202.0.0/16", "172.31.0.0/16")

# First line _override_resolv writes into /etc/resolv.conf — used to detect our
# own override during a stateless sweep.
_RESOLV_MARKER = "# vpn-chainer override"


@dataclass
class HostState:
    # Phase 1 (forwarding) — applies to the *carrier* veth (host ↔ ns1) so that
    # VPN_1's encrypted UDP can reach the wire via the host's physical NIC.
    orig_default_gw: str
    orig_default_iface: str
    carrier_outer_iface: str   # vpnc1o — host-side veth into ns_1
    base_prefix_cidr: str
    ip_forward_was: str
    forwarding_rules: list[list[str]] = field(default_factory=list)

    # Phase 2 (default redirect) — points the host default at the *ingress*
    # veth (host ↔ ns_N) so plaintext traffic enters the chain at the
    # innermost ns and gets wrapped by every VPN.
    redirect_done: bool = False
    ingress_outer_iface: str = ""  # vpncIo — host-side veth into ns_N
    ingress_inner_ip: str = ""     # 10.200.<N>.2 — gateway on ns_N side
    vpn1_server_ip: str = ""
    resolv_mode: str = ""          # "absent" | "regular" | "symlink"
    resolv_target: str = ""        # symlink target if resolv_mode == "symlink"
    resolv_backup_path: str = ""   # backup file path if resolv_mode == "regular"
    deny_direct_server_ips: list[str] = field(default_factory=list)
    deny_rules: list[list[str]] = field(default_factory=list)


def enable_chain_forwarding(topo: netns_mod.ChainTopology) -> HostState:
    if topo.ingress is None:
        raise RuntimeError("topology has no ingress veth — set up first")
    orig_gw, orig_iface = _read_default_route()
    carrier = topo.veth_to_ns(1)
    base_cidr = f"{topo.base_prefix}.0.0/16"

    state = HostState(
        orig_default_gw=orig_gw,
        orig_default_iface=orig_iface,
        carrier_outer_iface=carrier.outer_name,
        base_prefix_cidr=base_cidr,
        ip_forward_was=_read_ip_forward(),
    )
    log(f"original default: via {orig_gw} dev {orig_iface}")

    run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])

    rules = [
        ["-t", "nat", "-A", "POSTROUTING",
         "-s", base_cidr, "-o", orig_iface, "-j", "MASQUERADE"],
        ["-A", "FORWARD", "-i", carrier.outer_name, "-o", orig_iface, "-j", "ACCEPT"],
        ["-A", "FORWARD", "-i", orig_iface, "-o", carrier.outer_name,
         "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]
    for r in rules:
        run(["iptables", *r])
    state.forwarding_rules = rules

    log("host SNAT/forwarding active for chain subnets (default route untouched)")
    _save(state)
    return state


def redirect_default_route(
    state: HostState,
    topo: netns_mod.ChainTopology,
    *,
    vpn1_server_ip: str,
    keep_host_dns: bool = False,
    chain_dns: str = "1.1.1.1",
) -> None:
    """Pin VPN_1's endpoint, then point the host default at the ingress veth so
    host plaintext is wrapped by VPN_N first (innermost) and unwraps in order
    VPN_N → VPN_{N-1} → … → VPN_1 by the time it leaves via the carrier veth.
    """
    if topo.ingress is None:
        raise RuntimeError("topology has no ingress veth")

    state.vpn1_server_ip = vpn1_server_ip
    state.ingress_outer_iface = topo.ingress.outer_name
    state.ingress_inner_ip = topo.ingress.inner_ip

    # Pin VPN_1's encrypted carrier to the original gateway BEFORE moving the
    # default — otherwise the carrier would loop into the chain the moment we
    # replace default.
    run(["ip", "route", "replace", f"{vpn1_server_ip}/32",
         "via", state.orig_default_gw, "dev", state.orig_default_iface])

    # Anonymity guarantee: nothing on the host should ever talk directly to a
    # VPN server other than hop 1 over the physical NIC. Routing already
    # forces such traffic through the chain (default → ingress veth), but we
    # add explicit DROP rules so even a misconfigured route or a buggy app
    # binding to orig_iface cannot leak.
    state.deny_direct_server_ips = []  # populated by block_direct_hop_access

    run(["ip", "route", "replace", "default",
         "via", state.ingress_inner_ip, "dev", state.ingress_outer_iface])
    log(f"host default → {state.ingress_inner_ip} via {state.ingress_outer_iface} "
        f"(plaintext enters {topo.ingress.inner_ns} first)")

    if not keep_host_dns:
        _override_resolv(state, chain_dns)

    state.redirect_done = True
    _save(state)


def block_direct_hop_access(state: HostState, hop_server_ips: list[str]) -> None:
    """Add iptables DROP rules so the host cannot send packets to any hop ≥ 2's
    server IP directly over the physical NIC. Belt-and-suspenders on top of the
    routing table redirect: even if some app binds explicitly to orig_iface,
    these rules drop the packet.
    """
    rules: list[list[str]] = []
    for ip in hop_server_ips:
        for chain in ("OUTPUT", "FORWARD"):
            rules.append([
                "-A", chain, "-d", ip, "-o", state.orig_default_iface,
                "-j", "DROP",
            ])
    for r in rules:
        run(["iptables", *r])
    state.deny_direct_server_ips = list(hop_server_ips)
    state.deny_rules = rules
    if hop_server_ips:
        log(f"host: direct access to {len(hop_server_ips)} non-hop1 server IP(s) "
            f"DROPped on {state.orig_default_iface}")
    _save(state)


def restore(state: HostState | None = None) -> None:
    """Undo phase 2 first, then phase 1. Idempotent — safe on partial state."""
    if state is None:
        state = _load()
    if state is None:
        warn("no host_state.json — nothing to restore")
        return

    # Phase 2 restore.
    if state.redirect_done:
        try:
            run(["ip", "route", "replace", "default",
                 "via", state.orig_default_gw, "dev", state.orig_default_iface])
            log(f"host default restored → {state.orig_default_gw} dev {state.orig_default_iface}")
        except Exception as e:
            warn(f"failed to restore default route: {e}")
        if state.vpn1_server_ip:
            run(["ip", "route", "del", f"{state.vpn1_server_ip}/32"], check=False)
        _restore_resolv(state)

    # Anti-leak DROP rules (phase 2 add-on).
    for r in state.deny_rules:
        deletion = ["-D" if tok == "-A" else tok for tok in r]
        run(["iptables", *deletion], check=False)

    # Phase 1 restore.
    for r in state.forwarding_rules:
        deletion = ["-D" if tok == "-A" else tok for tok in r]
        run(["iptables", *deletion], check=False)

    if state.ip_forward_was in ("0", "1"):
        run(["sysctl", "-qw", f"net.ipv4.ip_forward={state.ip_forward_was}"], check=False)

    if STATE_FILE.exists():
        STATE_FILE.unlink()


def force_restore() -> None:
    """Restore the host even when host_state.json is missing or corrupt.

    Runs the precise, record-based `restore()` first when a state file exists,
    then sweeps the live kernel for any leftover vpn-chainer host mutations and
    undoes them by pattern: a lingering chain MASQUERADE rule, a default route
    still pointing through a chain veth (rebuilt from the surviving carrier /32
    pin, which itself encodes the original gateway), and an overridden
    /etc/resolv.conf. This is what lets `recover` un-wedge a host with no state
    on disk, so no manual recovery procedure is ever required.
    """
    st = _load()
    if st is not None:
        try:
            restore(st)
        except Exception as e:
            warn(f"state-based host restore raised: {e}")

    # Each sweep is independent — one raising must not skip the others.
    for sweep in (_sweep_masquerade, _sweep_default_route, _sweep_resolv):
        try:
            sweep()
        except Exception as e:
            warn(f"host sweep {sweep.__name__} raised: {e}")


# ───────────────────────────── Helpers ─────────────────────────────


def _read_default_route() -> tuple[str, str]:
    """Return (gateway_ip, dev) of the current IPv4 default route."""
    proc = run(["ip", "-4", "-j", "route", "show", "default"], check=False)
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            data = json.loads(proc.stdout)
            if data:
                entry = data[0]
                gw = entry.get("gateway", "")
                dev = entry.get("dev", "")
                if gw and dev:
                    return gw, dev
        except json.JSONDecodeError:
            pass
    proc = run(["ip", "-4", "route", "show", "default"], check=False)
    out = (proc.stdout or "").strip()
    if not out:
        raise RuntimeError("no IPv4 default route on host — cannot redirect")
    parts = out.splitlines()[0].split()
    gw = parts[parts.index("via") + 1] if "via" in parts else ""
    dev = parts[parts.index("dev") + 1] if "dev" in parts else ""
    if not gw or not dev:
        raise RuntimeError(f"could not parse default route: {out!r}")
    return gw, dev


def _read_ip_forward() -> str:
    p = Path("/proc/sys/net/ipv4/ip_forward")
    try:
        return p.read_text().strip()
    except OSError:
        return "0"


def _sweep_masquerade() -> None:
    """Drop any nat/POSTROUTING MASQUERADE rule whose source is EXACTLY one of
    the chain's own /16s — matched on the `-s` token, not a substring, so a
    user's own NAT on an overlapping/lookalike range is never touched."""
    proc = run(["iptables", "-t", "nat", "-S", "POSTROUTING"], check=False)
    for line in (proc.stdout or "").splitlines():
        if not line.startswith("-A POSTROUTING") or "MASQUERADE" not in line:
            continue
        toks = shlex.split(line)
        if "-s" not in toks:
            continue
        i = toks.index("-s")
        if i + 1 >= len(toks) or toks[i + 1] not in _CHAIN_PREFIXES:
            continue
        toks[0] = "-D"  # "-A POSTROUTING …" → "-D POSTROUTING …"
        run(["iptables", "-t", "nat", *toks], check=False)
        log("recover: removed leftover chain MASQUERADE rule")


def _default_route_dev() -> str:
    """dev of the current IPv4 default route, or '' if there is none."""
    proc = run(["ip", "-4", "-j", "route", "show", "default"], check=False)
    if proc.returncode == 0 and (proc.stdout or "").strip():
        try:
            data = json.loads(proc.stdout)
            if data:
                return data[0].get("dev", "")
        except json.JSONDecodeError:
            pass
    return ""


def _find_carrier_pin() -> tuple[str, str, str] | None:
    """Locate the leftover VPN_1 carrier pin route.

    `redirect_default_route` installs `ip route replace <vpn1>/32 via <orig_gw>
    dev <orig_iface>`, so even after host_state.json is gone this /32 host route
    still encodes the original gateway and physical interface. Returns
    (gw, dev, dst) or None. `ip -j` prints a bare address (no prefixlen) for a
    /32, which distinguishes it from the chain's /30 veth subnets.
    """
    proc = run(["ip", "-4", "-j", "route", "show"], check=False)
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return None
    for entry in data:
        dst = entry.get("dst", "")
        gw = entry.get("gateway", "")
        dev = entry.get("dev", "")
        if not gw or not dev or dev == "lo" or dev.startswith("vpnc"):
            continue
        if dst in ("default", "") or "/" in dst:
            continue
        return gw, dev, dst
    return None


def _sweep_default_route() -> None:
    """Rebuild the default route from the surviving carrier pin if it is missing
    or still points through a chain veth."""
    dev = _default_route_dev()
    if dev and not dev.startswith("vpnc"):
        return  # a normal default route is already in place — leave it alone
    pin = _find_carrier_pin()
    if pin is None:
        if not dev:
            warn("recover: no default route and no recoverable carrier pin — "
                 "set it manually: ip route add default via <gw> dev <iface>")
        return
    gw, iface, _dst = pin
    # Rebuild the default via the pinned gateway/iface. Deliberately do NOT
    # delete the /32 pin route: we only *guessed* it here (no state to confirm),
    # so deleting it risks removing a user's own static host route. Left in
    # place it is harmless — it merely routes that one ex-server IP via the same
    # gateway the default now uses.
    run(["ip", "route", "replace", "default", "via", gw, "dev", iface], check=False)
    log(f"recover: default route rebuilt from carrier pin → via {gw} dev {iface}")


def _sweep_resolv() -> None:
    """Restore /etc/resolv.conf if it still bears the vpn-chainer override marker."""
    try:
        if RESOLV_PATH.is_symlink() or not RESOLV_PATH.is_file():
            return
        first = RESOLV_PATH.read_text(errors="replace").splitlines()[:1]
        if not first or not first[0].startswith(_RESOLV_MARKER):
            return
        backup = PERSIST_DIR / "resolv-backup" / "resolv.conf"
        if backup.exists():
            RESOLV_PATH.write_text(backup.read_text(errors="replace"))
            backup.unlink()
            log("recover: /etc/resolv.conf restored from backup")
        else:
            RESOLV_PATH.write_text("nameserver 1.1.1.1\n")
            warn("recover: no resolv backup found — wrote a fallback nameserver; "
                 "set your preferred DNS in /etc/resolv.conf")
    except Exception as e:
        warn(f"recover: resolv sweep raised: {e}")


def _override_resolv(state: HostState, chain_dns: str) -> None:
    backup_dir = PERSIST_DIR / "resolv-backup"
    backup_dir.mkdir(parents=True, exist_ok=True)

    if RESOLV_PATH.is_symlink():
        state.resolv_mode = "symlink"
        state.resolv_target = os.readlink(RESOLV_PATH)
        RESOLV_PATH.unlink()
    elif RESOLV_PATH.is_file():
        state.resolv_mode = "regular"
        backup = backup_dir / "resolv.conf"
        backup.write_text(RESOLV_PATH.read_text(errors="replace"))
        state.resolv_backup_path = str(backup)
    else:
        state.resolv_mode = "absent"

    RESOLV_PATH.write_text(f"# vpn-chainer override\nnameserver {chain_dns}\n")
    log(f"host /etc/resolv.conf → {chain_dns} (will be restored)")


def _restore_resolv(state: HostState) -> None:
    try:
        if state.resolv_mode == "symlink":
            if RESOLV_PATH.exists() or RESOLV_PATH.is_symlink():
                RESOLV_PATH.unlink()
            os.symlink(state.resolv_target, RESOLV_PATH)
        elif state.resolv_mode == "regular":
            backup = Path(state.resolv_backup_path)
            if backup.exists():
                RESOLV_PATH.write_text(backup.read_text(errors="replace"))
                backup.unlink()
        elif state.resolv_mode == "absent":
            if RESOLV_PATH.exists() or RESOLV_PATH.is_symlink():
                RESOLV_PATH.unlink()
    except Exception as e:
        warn(f"failed to restore /etc/resolv.conf: {e}")


def _save(state: HostState) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state.__dict__, indent=2))


def _load() -> HostState | None:
    if not STATE_FILE.exists():
        return None
    try:
        data = json.loads(STATE_FILE.read_text())
    except json.JSONDecodeError:
        return None
    # Be tolerant of state files written by older versions: drop unknown keys
    # and rename a couple of known-renamed fields so an upgrade path that hits
    # 'recover' / 'down' still works without forcing the user to hand-edit
    # /var/lib/vpnchainer.
    if "veth_outer_iface" in data and "carrier_outer_iface" not in data:
        data["carrier_outer_iface"] = data.pop("veth_outer_iface")
    data.pop("ns1_inner_ip", None)
    known = {f.name for f in HostState.__dataclass_fields__.values()}
    unknown = set(data) - known
    if unknown:
        warn(f"host_state.json has unknown keys, ignoring: {sorted(unknown)}")
        for k in unknown:
            data.pop(k, None)
    try:
        return HostState(**data)
    except TypeError as e:
        warn(f"host_state.json could not be loaded: {e}")
        return None
