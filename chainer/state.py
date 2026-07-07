"""Persistent chain state — used by `up` to write, `down`/`status`/`recover` to read.

This module is the source of truth for "is a chain currently up, and what did
it change?". Everything written here lives in PERSIST_DIR so it survives
reboots, network restarts, and Python process death. After a reboot the kernel
state (namespaces, routes, iptables) is gone; the persisted records here let us
still restore /etc/resolv.conf and emit a clean recovery diff.
"""

from __future__ import annotations

import datetime
import json
import os
from dataclasses import dataclass

from . import host as host_mod
from . import netns as netns_mod
from .util import PERSIST_DIR

CHAIN_FILE = PERSIST_DIR / "chain.json"
HOPS_FILE = PERSIST_DIR / "hops.json"


@dataclass
class HopRecord:
    """Persistable subset of vpn.HopRuntime — only what teardown needs."""
    k: int
    kind: str          # "wireguard" | "openvpn"
    config_path: str
    server_host: str
    server_ip: str
    iface: str
    ovpn_pid: int | None = None
    ovpn_pidfile: str | None = None
    ovpn_logfile: str | None = None
    ovpn_credfile: str | None = None


@dataclass
class ChainRecord:
    """Top-level metadata about the running chain."""
    started_at: str
    n_hops: int
    redirect_host: bool
    keep_host_dns: bool
    chain_dns: str
    pid_who_built: int  # the python pid that ran 'up' — informational only


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def save_chain(rec: ChainRecord) -> None:
    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    CHAIN_FILE.write_text(json.dumps(rec.__dict__, indent=2))


def save_hops(hops: list[HopRecord]) -> None:
    PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    HOPS_FILE.write_text(json.dumps([h.__dict__ for h in hops], indent=2))


def load_chain() -> ChainRecord | None:
    if not CHAIN_FILE.exists():
        return None
    try:
        return ChainRecord(**json.loads(CHAIN_FILE.read_text()))
    except (json.JSONDecodeError, TypeError):
        return None


def load_hops() -> list[HopRecord]:
    if not HOPS_FILE.exists():
        return []
    try:
        data = json.loads(HOPS_FILE.read_text())
    except json.JSONDecodeError:
        return []
    return [HopRecord(**h) for h in data]


def delete_all() -> None:
    """Remove every persisted state file. Called only after a clean teardown."""
    for p in (CHAIN_FILE, HOPS_FILE):
        if p.exists():
            p.unlink()
    # netns and host modules clean up their own files in their teardown paths.


def state_present() -> bool:
    """True iff a previous `up` left state behind that hasn't been torn down."""
    return any(p.exists() for p in (
        CHAIN_FILE, HOPS_FILE, netns_mod.TOPO_FILE, host_mod.STATE_FILE,
    ))


def kernel_alive(topo: netns_mod.ChainTopology | None) -> bool:
    """True iff every namespace recorded in `topo` actually still exists.

    After a reboot the persisted state may say "chain up" while the kernel has
    no trace of it — this returns False in that case so callers can switch to
    recovery mode.
    """
    if topo is None:
        return False
    proc = os.popen("ip netns list").read()
    existing = {line.split()[0] for line in proc.splitlines() if line.strip()}
    return all(ns in existing for ns in topo.namespaces)
