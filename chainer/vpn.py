"""WireGuard and OpenVPN bring-up inside a network namespace.

For each hop the lifecycle is:
  1. Pre-bring-up: the inner namespace already has a provisional default route via
     the upstream-veth IP (see chainer.netns). This is what lets the VPN's encrypted
     transport reach the remote endpoint.
  2. Bring up the tunnel iface (wg or tun).
  3. Pin a /32 specific route to the VPN server's IP via the upstream-veth IP, so
     even after we replace the default with the tunnel, the encrypted carrier still
     routes correctly.
  4. Replace the namespace's default route with the tunnel iface.
  5. Apply MASQUERADE NAT on the tunnel iface (handled in chainer.netns
     `install_intermediate_nat`).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import netns as netns_mod
from .detect import HopConfig
from .util import log, run_in_ns, trace, warn


@dataclass
class HopRuntime:
    k: int  # 1-indexed hop position
    cfg: HopConfig
    iface: str = ""  # tunnel interface name in the ns
    proc: subprocess.Popen | None = None  # only for OpenVPN
    pidfile: Path | None = None
    logfile: Path | None = None
    credfile: Path | None = None  # OpenVPN auth-user-pass file (chmod 600)


class VpnError(RuntimeError):
    pass


def start_hop(topo: netns_mod.ChainTopology, k: int, cfg: HopConfig, *, dns_override: str | None = None) -> HopRuntime:
    upstream_gw = topo.upstream_gateway_for(k)
    ns = topo.ns(k)
    rt = HopRuntime(k=k, cfg=cfg)

    # Pin the encrypted endpoint to the upstream veth BEFORE we change the default.
    # The provisional default already points there, so this is redundant for now,
    # but it remains correct after we replace the default with the tunnel.
    run_in_ns(ns, ["ip", "route", "replace", f"{cfg.server_ip}/32", "via", upstream_gw])

    if cfg.kind == "wireguard":
        _bring_up_wireguard(ns, k, cfg, upstream_gw, rt, dns_override)
    else:
        _bring_up_openvpn(ns, k, cfg, upstream_gw, rt, dns_override)

    netns_mod.install_intermediate_nat(topo, k, rt.iface)
    netns_mod.apply_lockdown(topo, k, rt.iface)
    return rt


def stop_hop(rt: HopRuntime) -> None:
    if rt.proc is not None:
        _terminate(rt.proc)
        rt.proc = None
    elif rt.pidfile and rt.pidfile.exists():
        # Loaded from disk — terminate by pid alone.
        try:
            pid = int(rt.pidfile.read_text().strip())
            _terminate_by_pid(pid)
        except (ValueError, OSError):
            pass
    if rt.pidfile and rt.pidfile.exists():
        try:
            rt.pidfile.unlink()  # Path.unlink(missing_ok=True) is 3.8+, avoid.
        except FileNotFoundError:
            pass
    if rt.credfile and rt.credfile.exists():
        try:
            rt.credfile.unlink()
        except OSError:
            pass
    # The wg/tun interface is destroyed when its namespace is deleted by
    # chainer.netns.teardown — no separate work here.


# ───────────────────────────── WireGuard ─────────────────────────────


_WG_INTERFACE_KEYS = {"privatekey", "listenport", "fwmark"}
_WG_PEER_KEYS = {
    "publickey", "presharedkey", "endpoint", "allowedips",
    "persistentkeepalive",
}


def _bring_up_wireguard(
    ns: str,
    k: int,
    cfg: HopConfig,
    upstream_gw: str,
    rt: HopRuntime,
    dns_override: str | None,
) -> None:
    if not shutil.which("wg"):
        raise VpnError(
            "wireguard-tools not installed (need 'wg' binary). "
            "Install with: sudo apt install wireguard-tools"
        )

    parsed = _parse_wg_config(cfg.path)
    iface = f"wgc{k}"
    rt.iface = iface

    # Replace hostname endpoint with the pre-resolved IP — wg(8)'s setconf does
    # libc resolution, but in-namespace DNS may not be reachable yet for the
    # carrier's first packet (resolv.conf points to a public DNS that requires
    # the chain forwarding to be already established — which it is by this
    # point). Substituting the IP eliminates that dependency entirely.
    for peer in parsed.peers:
        ep = peer.get("endpoint", "")
        if ep and ":" in ep:
            host, _, port = ep.rpartition(":")
            if host == cfg.server_host:
                peer["endpoint"] = f"{cfg.server_ip}:{port}"

    run_in_ns(ns, ["ip", "link", "add", iface, "type", "wireguard"])

    # Write wg-only config (strip Address/DNS/PostUp etc. that wg(8) rejects).
    wg_only = _serialize_wg_config(parsed)
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as tf:
        tf.write(wg_only)
        wg_cfg_path = tf.name
    try:
        run_in_ns(ns, ["wg", "setconf", iface, wg_cfg_path])
    finally:
        os.unlink(wg_cfg_path)

    for addr in parsed.addresses:
        run_in_ns(ns, ["ip", "addr", "add", addr, "dev", iface])

    run_in_ns(ns, ["ip", "link", "set", iface, "up"])

    # Replace default with the tunnel.
    run_in_ns(ns, ["ip", "route", "replace", "default", "dev", iface])

    # MTU for nested tunnels is finicky; clamp MSS to be safe.
    run_in_ns(ns, [
        "iptables", "-t", "mangle", "-A", "FORWARD",
        "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ])

    _write_ns_resolv(ns, parsed.dns or ([dns_override] if dns_override else ["1.1.1.1"]))

    # Trigger a handshake: WG only initiates one when traffic needs to traverse
    # the tunnel, so kick a single ping (it will fail if the tunnel isn't up
    # yet, but the failure itself causes wireguard to start the handshake).
    run_in_ns(ns, ["ping", "-c", "1", "-W", "2", "-q", "1.1.1.1"], check=False)
    _wait_for_wg_handshake(ns, iface, timeout_s=30)


@dataclass
class _WgParsed:
    privatekey: str = ""
    listenport: str | None = None
    fwmark: str | None = None
    addresses: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    peers: list[dict[str, str]] = field(default_factory=list)


def _parse_wg_config(path: Path) -> _WgParsed:
    out = _WgParsed()
    section: str | None = None
    cur_peer: dict[str, str] | None = None
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            sect = line[1:-1].strip().lower()
            if sect == "interface":
                section = "interface"
            elif sect == "peer":
                if cur_peer is not None:
                    out.peers.append(cur_peer)
                cur_peer = {}
                section = "peer"
            else:
                section = None
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()
        if section == "interface":
            if key == "privatekey":
                out.privatekey = val
            elif key == "listenport":
                out.listenport = val
            elif key == "fwmark":
                out.fwmark = val
            elif key == "address":
                out.addresses.extend(a.strip() for a in val.split(","))
            elif key == "dns":
                out.dns.extend(d.strip() for d in val.split(","))
        elif section == "peer" and cur_peer is not None:
            cur_peer[key] = val
    if cur_peer is not None:
        out.peers.append(cur_peer)
    if not out.privatekey:
        raise VpnError(f"{path}: WireGuard [Interface] missing PrivateKey")
    if not out.peers:
        raise VpnError(f"{path}: WireGuard config has no [Peer] block")
    return out


def _serialize_wg_config(p: _WgParsed) -> str:
    lines = ["[Interface]", f"PrivateKey = {p.privatekey}"]
    if p.listenport:
        lines.append(f"ListenPort = {p.listenport}")
    if p.fwmark:
        lines.append(f"FwMark = {p.fwmark}")
    for peer in p.peers:
        lines.append("")
        lines.append("[Peer]")
        for k in ("publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"):
            if k in peer:
                cap = {
                    "publickey": "PublicKey",
                    "presharedkey": "PresharedKey",
                    "endpoint": "Endpoint",
                    "allowedips": "AllowedIPs",
                    "persistentkeepalive": "PersistentKeepalive",
                }[k]
                lines.append(f"{cap} = {peer[k]}")
    lines.append("")
    return "\n".join(lines)


def _wait_for_wg_handshake(ns: str, iface: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_kick = 0.0
    while time.monotonic() < deadline:
        proc = run_in_ns(ns, ["wg", "show", iface, "latest-handshakes"], check=False)
        out = (proc.stdout or "").strip()
        # Lines are "<pubkey>\t<unix_ts>"
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[-1].isdigit() and int(parts[-1]) > 0:
                return
        # Re-kick handshake every 5 s since WG only initiates on outbound traffic.
        now = time.monotonic()
        if now - last_kick > 5.0:
            run_in_ns(ns, ["ping", "-c", "1", "-W", "1", "-q", "1.1.1.1"], check=False)
            last_kick = now
        time.sleep(0.5)
    raise VpnError(f"WireGuard {iface} in {ns}: no handshake within {timeout_s}s")


# ───────────────────────────── OpenVPN ─────────────────────────────


_OVPN_TUN_OPENED = re.compile(r"TUN/TAP device (\S+) opened")
_OVPN_INIT_DONE = re.compile(r"Initialization Sequence Completed")


def _bring_up_openvpn(
    ns: str,
    k: int,
    cfg: HopConfig,
    upstream_gw: str,
    rt: HopRuntime,
    dns_override: str | None,
) -> None:
    log_dir = netns_mod.STATE_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    rt.logfile = log_dir / f"ovpn-{k}.log"
    rt.pidfile = netns_mod.STATE_DIR / f"ovpn-{k}.pid"
    if rt.pidfile.exists():
        rt.pidfile.unlink()

    argv = [
        "ip", "netns", "exec", ns,
        "openvpn",
        "--config", str(cfg.path),
        "--route-noexec",            # we install routes ourselves
        "--writepid", str(rt.pidfile),
        "--verb", "3",
    ]

    if cfg.needs_credentials:
        if not cfg.username or cfg.password is None:
            raise VpnError(
                f"hop {k}: openvpn config {cfg.path} expects credentials but "
                f"none were collected (cfg.username/password are empty)"
            )
        rt.credfile = _write_credentials(k, cfg.username, cfg.password)
        argv += ["--auth-user-pass", str(rt.credfile)]

    log(f"openvpn launching in {ns} with config {cfg.path}")

    rt.logfile.write_text("")  # truncate
    log_fh = open(rt.logfile, "a", buffering=1)  # line-buffered
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    rt.proc = proc

    iface = _wait_for_openvpn_init(rt.logfile, proc, timeout_s=45)
    rt.iface = iface

    run_in_ns(ns, ["ip", "route", "replace", "default", "dev", iface])
    run_in_ns(ns, [
        "iptables", "-t", "mangle", "-A", "FORWARD",
        "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ])

    _write_ns_resolv(ns, [dns_override] if dns_override else ["1.1.1.1"])


def _write_credentials(k: int, username: str, password: str) -> Path:
    """Write OpenVPN auth-user-pass file (chmod 600). Caller deletes on stop."""
    cred_dir = netns_mod.STATE_DIR / "creds"
    cred_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(cred_dir, 0o700)
    path = cred_dir / f"ovpn-{k}.cred"
    # Open with O_CREAT|O_EXCL|O_WRONLY at 0o600 so the file is never
    # world-readable, even briefly.
    fd = os.open(
        str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600,
    )
    try:
        os.write(fd, f"{username}\n{password}\n".encode("utf-8"))
    finally:
        os.close(fd)
    return path


def _wait_for_openvpn_init(
    logfile: Path,
    proc: subprocess.Popen,
    timeout_s: float,
) -> str:
    deadline = time.monotonic() + timeout_s
    iface: str | None = None
    last_size = 0
    while time.monotonic() < deadline:
        rc = proc.poll()
        if rc is not None:
            tail = ""
            if logfile.exists():
                tail = logfile.read_text(errors="replace")[-2000:]
            raise VpnError(
                f"openvpn exited early (rc={rc}). Last log:\n{tail}"
            )
        if not logfile.exists():
            time.sleep(0.2)
            continue
        size = logfile.stat().st_size
        if size > last_size:
            text = logfile.read_text(errors="replace")
            if iface is None:
                m = _OVPN_TUN_OPENED.search(text)
                if m:
                    iface = m.group(1)
                    trace(f"openvpn opened tun: {iface}")
            if iface and _OVPN_INIT_DONE.search(text):
                return iface
            last_size = size
        time.sleep(0.4)
    raise VpnError(
        f"openvpn did not finish initialization within {timeout_s}s "
        f"(check {logfile})"
    )


# ───────────────────────────── DNS ─────────────────────────────


def _write_ns_resolv(ns: str, servers: list[str]) -> None:
    """Per-namespace resolv.conf; mounted automatically by `ip netns exec` runs."""
    cleaned = [s for s in servers if s]
    if not cleaned:
        return
    d = Path("/etc/netns") / ns
    d.mkdir(parents=True, exist_ok=True)
    body = "".join(f"nameserver {s}\n" for s in cleaned)
    (d / "resolv.conf").write_text(body)


def cleanup_ns_resolv(ns: str) -> None:
    p = Path("/etc/netns") / ns / "resolv.conf"
    if p.exists():
        p.unlink()
    parent = Path("/etc/netns") / ns
    if parent.exists():
        try:
            parent.rmdir()
        except OSError:
            pass


# ───────────────────────────── Process termination ─────────────────────────────


def _terminate(proc: subprocess.Popen, *, term_grace_s: float = 5.0) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=term_grace_s)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        warn(f"openvpn pid {proc.pid} did not exit after SIGKILL")


def _terminate_by_pid(pid: int, *, term_grace_s: float = 5.0) -> None:
    """Terminate a process we don't own a Popen handle for (loaded from disk)."""
    import signal as _signal
    if pid <= 1:
        return
    try:
        os.kill(pid, _signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + term_grace_s
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.2)
    try:
        os.kill(pid, _signal.SIGKILL)
    except ProcessLookupError:
        return
    time.sleep(0.5)
    try:
        os.kill(pid, 0)
        warn(f"openvpn pid {pid} did not exit after SIGKILL")
    except ProcessLookupError:
        pass
