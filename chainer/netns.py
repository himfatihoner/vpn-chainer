"""Network namespace, veth pair, and NAT setup/teardown.

Topology (N hops):
    default_ns ── veth(h-1) ── ns1 ── veth(1-2) ── ns2 ── ... ── nsN

Each veth pair uses a /30 subnet from 10.200.X.0/30. Host-side IP is .1, ns-side is .2.

After bring-up (with VPN tunnels installed in each ns by chainer.vpn):
- ns_k default route points at its VPN tunnel iface
- ns_k MASQUERADEs forwarded packets out the VPN tunnel iface (so deeper ns traffic
  emerges as the VPN tunnel's source IP)
- Host MASQUERADEs only the encrypted VPN1 traffic out the physical NIC (handled in
  chainer.host when redirecting the default route).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

from .util import PERSIST_DIR, RUN_DIR, log, run, run_in_ns, trace

# Topology JSON lives in PERSIST_DIR — must outlive reboots so 'down' / 'recover'
# can roll back. Ephemeral artifacts (logs, pids) go under RUN_DIR. STATE_DIR is
# kept as a back-compat alias for code that still references it for ephemeral
# files; new code should reference PERSIST_DIR / RUN_DIR explicitly.
STATE_DIR = RUN_DIR
TOPO_FILE = PERSIST_DIR / "topology.json"

DEFAULT_BASE_PREFIX = "10.200"
FALLBACK_PREFIXES = ["10.201", "10.202", "172.31"]


@dataclass
class VethPair:
    """A veth pair connecting two namespaces (or host↔ns1).

    `outer_*` lives in the upstream side (host or ns_{k-1}).
    `inner_*` lives in the downstream namespace (ns_k).
    """
    outer_name: str
    inner_name: str
    outer_ns: str  # "" means default ns (host)
    inner_ns: str
    outer_ip: str
    inner_ip: str
    cidr: str  # e.g. "10.200.0.0/30"


@dataclass
class ChainTopology:
    n_hops: int
    base_prefix: str
    namespaces: list[str] = field(default_factory=list)  # ["ns1", "ns2", ...]
    veths: list[VethPair] = field(default_factory=list)  # len == n_hops; veths[0] = host↔ns1
    # Ingress veth between host and the *innermost* ns (ns_N). This is what the
    # host's default route is redirected to — host plaintext enters here, gets
    # wrapped by VPN_N first (innermost wrap), then VPN_{N-1}, …, VPN_1, then
    # the resulting fully-encrypted carrier exits via the ns1↔host veth.
    ingress: VethPair | None = None

    def ns(self, k: int) -> str:
        """1-indexed namespace name."""
        return self.namespaces[k - 1]

    def veth_to_ns(self, k: int) -> VethPair:
        """The veth pair whose inner side lives in ns_k."""
        return self.veths[k - 1]

    def upstream_gateway_for(self, k: int) -> str:
        """The outer-side IP of the veth landing in ns_k (used as ns_k's default gw)."""
        return self.veths[k - 1].outer_ip


def setup_topology(n_hops: int, *, boot_dns: str = "1.1.1.1") -> ChainTopology:
    """Allocate subnets, create namespaces, veth pairs, and basic IP plumbing.

    Does NOT install default routes or NAT for VPN tunnels — that happens in
    chainer.vpn.start_hop after the tunnel iface exists.

    `boot_dns` is written to /etc/netns/<ns>/resolv.conf so that VPN clients can
    resolve hostname endpoints during bring-up (this requires host SNAT to be in
    place — see chainer.host.enable_chain_forwarding).
    """
    if n_hops < 1 or n_hops > 8:
        raise ValueError("n_hops must be between 1 and 8")

    base = _choose_base_prefix(n_hops)
    topo = ChainTopology(n_hops=n_hops, base_prefix=base)

    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    RUN_DIR.mkdir(parents=True, exist_ok=True)

    log(f"Using subnet base {base}.0.0/16")
    for k in range(1, n_hops + 1):
        ns = f"vpnchain_ns{k}"
        run(["ip", "netns", "add", ns])
        topo.namespaces.append(ns)
        run_in_ns(ns, ["ip", "link", "set", "lo", "up"])
        run_in_ns(ns, ["sysctl", "-qw", "net.ipv4.ip_forward=1"])
        run_in_ns(ns, ["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"])
        run_in_ns(ns, ["sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1"])
        _write_boot_resolv(ns, boot_dns)

    for k in range(1, n_hops + 1):
        upstream = "" if k == 1 else topo.namespaces[k - 2]
        downstream = topo.namespaces[k - 1]
        cidr = f"{base}.{k - 1}.0/30"
        outer_ip = f"{base}.{k - 1}.1"
        inner_ip = f"{base}.{k - 1}.2"
        outer_name = f"vpnc{k}o"
        inner_name = f"vpnc{k}i"

        run(["ip", "link", "add", outer_name, "type", "veth", "peer", "name", inner_name])

        if upstream:
            run(["ip", "link", "set", outer_name, "netns", upstream])
            run_in_ns(upstream, ["ip", "addr", "add", f"{outer_ip}/30", "dev", outer_name])
            run_in_ns(upstream, ["ip", "link", "set", outer_name, "up"])
        else:
            run(["ip", "addr", "add", f"{outer_ip}/30", "dev", outer_name])
            run(["ip", "link", "set", outer_name, "up"])

        run(["ip", "link", "set", inner_name, "netns", downstream])
        run_in_ns(downstream, ["ip", "addr", "add", f"{inner_ip}/30", "dev", inner_name])
        run_in_ns(downstream, ["ip", "link", "set", inner_name, "up"])

        # Provisional default route in the inner ns: send unknown traffic upstream.
        # This will be replaced by the VPN tunnel route after bring-up. The provisional
        # route is what lets the VPN's encrypted UDP reach its remote endpoint.
        run_in_ns(downstream, ["ip", "route", "replace", "default", "via", outer_ip])

        topo.veths.append(VethPair(
            outer_name=outer_name,
            inner_name=inner_name,
            outer_ns=upstream,
            inner_ns=downstream,
            outer_ip=outer_ip,
            inner_ip=inner_ip,
            cidr=cidr,
        ))
        log(f"ns{k}: {downstream} via {outer_ip} ({cidr})")

    # Ingress veth: host ↔ ns_N. This is what the host's default route is
    # redirected to in chainer.host.redirect_default_route. Plaintext from the
    # host enters ns_N here, gets wrapped by VPN_N (innermost), then bubbles
    # outward through the chain.
    last_ns = topo.namespaces[-1]
    ing_cidr = f"{base}.{n_hops}.0/30"
    ing_outer_ip = f"{base}.{n_hops}.1"
    ing_inner_ip = f"{base}.{n_hops}.2"
    ing_outer_name = "vpncIo"
    ing_inner_name = "vpncIi"

    run(["ip", "link", "add", ing_outer_name, "type", "veth", "peer", "name", ing_inner_name])
    run(["ip", "addr", "add", f"{ing_outer_ip}/30", "dev", ing_outer_name])
    run(["ip", "link", "set", ing_outer_name, "up"])
    run(["ip", "link", "set", ing_inner_name, "netns", last_ns])
    run_in_ns(last_ns, ["ip", "addr", "add", f"{ing_inner_ip}/30", "dev", ing_inner_name])
    run_in_ns(last_ns, ["ip", "link", "set", ing_inner_name, "up"])

    topo.ingress = VethPair(
        outer_name=ing_outer_name,
        inner_name=ing_inner_name,
        outer_ns="",
        inner_ns=last_ns,
        outer_ip=ing_outer_ip,
        inner_ip=ing_inner_ip,
        cidr=ing_cidr,
    )
    log(f"ingress veth: host {ing_outer_ip} ↔ {last_ns} {ing_inner_ip} ({ing_cidr})")

    _save_topology(topo)
    return topo


def install_intermediate_nat(topo: ChainTopology, k: int, vpn_iface: str) -> None:
    """After VPN_k is up in ns_k, MASQUERADE forwarded traffic out its tunnel.

    Filter-chain rules are intentionally left to `apply_lockdown` so the chain's
    default-DROP policy can't be undermined by a blanket -j ACCEPT here.
    """
    ns = topo.ns(k)
    run_in_ns(ns, [
        "iptables", "-t", "nat", "-A", "POSTROUTING",
        "-o", vpn_iface, "-j", "MASQUERADE",
    ])


def apply_lockdown(topo: ChainTopology, k: int, vpn_iface: str) -> None:
    """Default-DROP firewall in ns_k (kill switch / lockdown).

    Only allows the exact flows the chain needs:
      - OUTPUT to the VPN tunnel iface (plaintext that wg/ovpn will encrypt) and
        to the upstream veth (the encrypted carrier UDP locally generated by the
        wg socket / openvpn process).
      - INPUT from the upstream veth (encrypted-carrier replies destined for our
        wg socket).
      - FORWARD only between the downstream veth (toward deeper ns or host's
        ingress veth in the case of ns_N) and the VPN tunnel iface — never to or
        from the upstream veth, which would let plaintext or partially-wrapped
        traffic skip a hop.
      - lo always allowed.
      - Conntrack RELATED/ESTABLISHED on every chain so replies make it back.

    Side effect: if the tunnel iface is later forced down (link drop, VPN
    process killed) the FORWARD rule's -o vpn_iface becomes effectively dead and
    the policy DROP catches everything — chain fails closed, no leakage to the
    upstream veth or out the wire un-encrypted.
    """
    ns = topo.ns(k)
    upstream_iface = topo.veths[k - 1].inner_name  # toward less-deep ns / host
    if k == topo.n_hops:
        if topo.ingress is None:
            raise RuntimeError(
                "topology missing ingress veth — cannot lock down the innermost ns"
            )
        downstream_iface = topo.ingress.inner_name
    else:
        downstream_iface = topo.veths[k].outer_name  # toward deeper ns

    # Flush filter chains so any earlier blanket rules don't bypass policy DROP.
    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        run_in_ns(ns, ["iptables", "-F", chain])
        run_in_ns(ns, ["iptables", "-P", chain, "DROP"])

    # Loopback always.
    run_in_ns(ns, ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run_in_ns(ns, ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

    # Conntrack returns on every chain.
    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        run_in_ns(ns, [
            "iptables", "-A", chain,
            "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
            "-j", "ACCEPT",
        ])

    # Local sockets (curl/ping inside the ns + the wg/ovpn underlay socket).
    run_in_ns(ns, ["iptables", "-A", "OUTPUT", "-o", vpn_iface, "-j", "ACCEPT"])
    run_in_ns(ns, ["iptables", "-A", "OUTPUT", "-o", upstream_iface, "-j", "ACCEPT"])

    # Encrypted-carrier replies arriving on the upstream veth.
    run_in_ns(ns, ["iptables", "-A", "INPUT", "-i", upstream_iface, "-j", "ACCEPT"])

    # The legitimate plaintext-bubble path: in from deeper, out via tunnel
    # (and vice-versa for decrypted replies).
    run_in_ns(ns, [
        "iptables", "-A", "FORWARD",
        "-i", downstream_iface, "-o", vpn_iface, "-j", "ACCEPT",
    ])
    run_in_ns(ns, [
        "iptables", "-A", "FORWARD",
        "-i", vpn_iface, "-o", downstream_iface, "-j", "ACCEPT",
    ])

    # IPv6 belt-and-suspenders (sysctl already disabled the stack, but if
    # something re-enables it we still drop everything).
    for chain in ("INPUT", "OUTPUT", "FORWARD"):
        run_in_ns(ns, ["ip6tables", "-P", chain, "DROP"], check=False)
        run_in_ns(ns, ["ip6tables", "-F", chain], check=False)

    log(f"{ns}: lockdown active (downstream={downstream_iface} "
        f"→ tunnel={vpn_iface} → upstream={upstream_iface}, default DROP)")


def teardown(topo: ChainTopology | None) -> None:
    """Best-effort: delete all namespaces (which also removes their interfaces and
    the inner side of veths). Then make sure host-side veth0 is gone too.
    """
    if topo is None:
        topo = _load_topology()
    if topo is None:
        # Nothing recorded — try to delete by name pattern as fallback.
        _teardown_by_pattern()
        return

    for v in topo.veths:
        if v.outer_ns == "":
            # host side: deleting the ns will remove the inner end; the outer end
            # then dangles. Delete it explicitly.
            run(["ip", "link", "del", v.outer_name], check=False)

    if topo.ingress is not None:
        run(["ip", "link", "del", topo.ingress.outer_name], check=False)

    for ns in topo.namespaces:
        run(["ip", "netns", "del", ns], check=False)

    if TOPO_FILE.exists():
        TOPO_FILE.unlink()


def _write_boot_resolv(ns: str, dns: str) -> None:
    """Pre-tunnel DNS so wg/openvpn can resolve hostname endpoints."""
    d = Path("/etc/netns") / ns
    d.mkdir(parents=True, exist_ok=True)
    (d / "resolv.conf").write_text(f"nameserver {dns}\n")


def _save_topology(topo: ChainTopology) -> None:
    data = {
        "n_hops": topo.n_hops,
        "base_prefix": topo.base_prefix,
        "namespaces": topo.namespaces,
        "veths": [v.__dict__ for v in topo.veths],
        "ingress": (topo.ingress.__dict__ if topo.ingress else None),
    }
    TOPO_FILE.write_text(json.dumps(data, indent=2))


def load_topology() -> ChainTopology | None:
    if not TOPO_FILE.exists():
        return None
    try:
        data = json.loads(TOPO_FILE.read_text())
    except json.JSONDecodeError:
        return None
    topo = ChainTopology(
        n_hops=data["n_hops"],
        base_prefix=data["base_prefix"],
        namespaces=list(data["namespaces"]),
    )
    topo.veths = [VethPair(**v) for v in data["veths"]]
    ing = data.get("ingress")
    topo.ingress = VethPair(**ing) if ing else None
    return topo


_load_topology = load_topology  # back-compat


def _teardown_by_pattern() -> None:
    """Last-resort cleanup when topology.json is missing."""
    proc = run(["ip", "-j", "netns", "list"], check=False)
    if proc.returncode != 0:
        # Older iproute2 may not support -j; fall back to plain.
        proc = run(["ip", "netns", "list"], check=False)
        names = [line.split()[0] for line in (proc.stdout or "").splitlines() if line.startswith("vpnchain_ns")]
    else:
        try:
            data = json.loads(proc.stdout or "[]")
            names = [d["name"] for d in data if d.get("name", "").startswith("vpnchain_ns")]
        except json.JSONDecodeError:
            names = []
    for ns in names:
        run(["ip", "netns", "del", ns], check=False)
    proc = run(["ip", "-o", "link"], check=False)
    for line in (proc.stdout or "").splitlines():
        # link names look like "  3: vpnc1o@if4: <...>" or "  5: vpncIo@if6: <...>"
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].split("@", 1)[0].strip()
        if name.startswith("vpnc") and name.endswith(("o", "i")):
            run(["ip", "link", "del", name], check=False)


def _choose_base_prefix(n_hops: int) -> str:
    """Pick the first /16 base whose required /30s don't conflict with existing routes."""
    candidates = [DEFAULT_BASE_PREFIX, *FALLBACK_PREFIXES]
    for base in candidates:
        if _is_prefix_free(base, n_hops):
            return base
    raise RuntimeError(
        "No free private subnet found among 10.200/16, 10.201/16, 10.202/16, 172.31/16. "
        "Free up routing table and retry."
    )


def _is_prefix_free(base: str, n_hops: int) -> bool:
    proc = run(["ip", "-4", "route", "show"], check=False)
    out = proc.stdout or ""
    # n_hops chain veths plus 1 ingress veth (host ↔ ns_N) → n_hops+1 /30 subnets.
    needed = [ipaddress.ip_network(f"{base}.{k}.0/30") for k in range(n_hops + 1)]
    for line in out.splitlines():
        first = line.split()[0] if line else ""
        try:
            net = ipaddress.ip_network(first, strict=False)
        except ValueError:
            continue
        for n in needed:
            if net.overlaps(n):
                trace(f"prefix {base}.* conflicts with route {line.strip()}")
                return False
    return True
