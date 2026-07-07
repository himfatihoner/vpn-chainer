"""Orchestrator — non-blocking build, separate teardown, recovery from disk.

Lifecycle:
  build_chain(configs)   → kernel state set up, persisted to disk, returns.
                           The Python process can exit; OpenVPN keeps running
                           because Popen used start_new_session=True. WireGuard
                           lives in the kernel and survives the script exit.
  teardown_chain()       → reads persisted state from disk and rolls back.
                           Idempotent and safe even after a reboot (when only
                           on-disk artifacts like /etc/resolv.conf still need
                           restoring).
  chain_status()         → returns a dict describing what's recorded and
                           whether the kernel still has it.
  recover()              → forced cleanup: tears down everything we can find by
                           name pattern, then deletes state files. Useful after
                           kill -9 or after a reboot left orphan state.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import host as host_mod
from . import netns as netns_mod
from . import postcheck as postcheck_mod
from . import state as state_mod
from . import verify as verify_mod
from . import vpn as vpn_mod
from .detect import HopConfig
from .util import err, log, warn


@dataclass
class ChainSession:
    """In-memory state during a single `up` invocation."""
    topo: netns_mod.ChainTopology | None = None
    hops: list[vpn_mod.HopRuntime] = field(default_factory=list)
    host: host_mod.HostState | None = None


def build_chain(
    configs: list[HopConfig],
    *,
    redirect_host: bool = True,
    keep_host_dns: bool = False,
    chain_dns: str = "1.1.1.1",
) -> ChainSession:
    """Build a chain end-to-end. Returns once everything is in place.

    On any failure during build, performs a rollback of partial state before
    re-raising.
    """
    if state_mod.state_present():
        raise RuntimeError(
            "previous chain state found on disk — run 'down' or 'recover' first"
        )
    if not configs:
        raise ValueError("at least one hop is required")

    sess = ChainSession()
    success = False
    try:
        sess.topo = netns_mod.setup_topology(len(configs), boot_dns=chain_dns)
        sess.host = host_mod.enable_chain_forwarding(sess.topo)

        exit_ips: list[str | None] = []
        for k, cfg in enumerate(configs, 1):
            log(f"bringing up hop {k} ({cfg.kind}) — {cfg.server_host}:{cfg.server_port}")
            rt = vpn_mod.start_hop(sess.topo, k, cfg, dns_override=chain_dns)
            sess.hops.append(rt)
            ip = verify_mod.probe_exit_ip(sess.topo.ns(k))
            exit_ips.append(ip)
            if ip:
                log(f"hop {k} exit IP: {ip}")
            else:
                warn(f"hop {k}: exit IP probe failed (chain may still be functional)")

        verify_mod.whole_chain_summary(sess.topo, exit_ips)

        if redirect_host:
            host_mod.redirect_default_route(
                sess.host,
                sess.topo,
                vpn1_server_ip=configs[0].server_ip,
                keep_host_dns=keep_host_dns,
                chain_dns=chain_dns,
            )
            # Anonymity guarantee: deny direct host→hop_K (K≥2) on the wire.
            host_mod.block_direct_hop_access(
                sess.host,
                [c.server_ip for c in configs[1:]],
            )

        # Persist everything before declaring success — so a failure during the
        # post-up verification still leaves a clean teardown path via 'down'.
        _persist_session(
            sess,
            redirect_host=redirect_host,
            keep_host_dns=keep_host_dns,
            chain_dns=chain_dns,
        )

        if redirect_host:
            time.sleep(1.0)  # let routing/conntrack settle
            verify_mod.final_traceroute()

        # Inline anonymity / leak verification — runs every time the chain is
        # built so the user gets immediate feedback on whether to trust it.
        postcheck_mod.run_anonymity_check(sess.topo, configs, sess.host)

        success = True
        return sess
    finally:
        if not success:
            warn("build failed; rolling back partial setup…")
            try:
                _teardown_session(sess)
            except Exception as e:
                err(f"rollback raised: {e}")


# ─────────────────────────── teardown / status / recover ───────────────────────────


def teardown_chain() -> None:
    """Read persisted state and tear everything down. Safe across reboots."""
    if not state_mod.state_present():
        warn("no chain state on disk — nothing to do")
        return

    topo = netns_mod.load_topology()
    hops_records = state_mod.load_hops()
    host_state = host_mod._load()  # type: ignore[attr-defined]

    # Rebuild lightweight HopRuntime entries so vpn.stop_hop can work uniformly.
    hops: list[vpn_mod.HopRuntime] = []
    for rec in hops_records:
        rt = _hop_runtime_from_record(rec)
        hops.append(rt)

    sess = ChainSession(topo=topo, hops=hops, host=host_state)
    _teardown_session(sess)


def chain_status() -> dict[str, Any]:
    """Return a status dict suitable for human reporting."""
    if not state_mod.state_present():
        return {"present": False}

    chain = state_mod.load_chain()
    topo = netns_mod.load_topology()
    hops_records = state_mod.load_hops()
    host_state = host_mod._load()  # type: ignore[attr-defined]
    alive = state_mod.kernel_alive(topo)

    return {
        "present": True,
        "alive": alive,
        "started_at": chain.started_at if chain else None,
        "n_hops": chain.n_hops if chain else (topo.n_hops if topo else 0),
        "redirect_done": (host_state.redirect_done if host_state else False),
        "host_orig_default": (
            f"{host_state.orig_default_gw} dev {host_state.orig_default_iface}"
            if host_state else None
        ),
        "namespaces": (topo.namespaces if topo else []),
        "hops": [
            {
                "k": h.k,
                "kind": h.kind,
                "config": h.config_path,
                "server": h.server_host,
                "server_ip": h.server_ip,
                "iface": h.iface,
                "ovpn_pid": h.ovpn_pid,
                "ovpn_alive": _pid_alive(h.ovpn_pid) if h.ovpn_pid else None,
            }
            for h in hops_records
        ],
    }


def recover() -> None:
    """Forced cleanup — tears down by state if present, then by name pattern.

    Use this after a `kill -9`, after a reboot that left /etc/resolv.conf in an
    overridden state, or whenever `status` shows present-but-not-alive.
    """
    if state_mod.state_present():
        log("found persisted state — running normal teardown first…")
        try:
            teardown_chain()
        except Exception as e:
            warn(f"teardown raised during recover: {e}")

    log("scanning for leftover namespaces / interfaces by name pattern…")
    netns_mod.teardown(None)  # falls back to pattern-based cleanup

    # If host_state.json still exists (e.g. teardown failed), try once more.
    if host_mod.STATE_FILE.exists():
        try:
            host_mod.restore(None)
        except Exception as e:
            warn(f"host restore on recover raised: {e}")

    state_mod.delete_all()
    log("recover complete")


# ─────────────────────────── helpers ───────────────────────────


def _persist_session(
    sess: ChainSession,
    *,
    redirect_host: bool,
    keep_host_dns: bool,
    chain_dns: str,
) -> None:
    import os
    chain_rec = state_mod.ChainRecord(
        started_at=state_mod.now_iso(),
        n_hops=len(sess.hops),
        redirect_host=redirect_host,
        keep_host_dns=keep_host_dns,
        chain_dns=chain_dns,
        pid_who_built=os.getpid(),
    )
    state_mod.save_chain(chain_rec)

    hop_records: list[state_mod.HopRecord] = []
    for rt in sess.hops:
        pid = rt.proc.pid if rt.proc is not None else None
        hop_records.append(state_mod.HopRecord(
            k=rt.k,
            kind=rt.cfg.kind,
            config_path=str(rt.cfg.path),
            server_host=rt.cfg.server_host,
            server_ip=rt.cfg.server_ip,
            iface=rt.iface,
            ovpn_pid=pid,
            ovpn_pidfile=str(rt.pidfile) if rt.pidfile else None,
            ovpn_logfile=str(rt.logfile) if rt.logfile else None,
            ovpn_credfile=str(rt.credfile) if rt.credfile else None,
        ))
    state_mod.save_hops(hop_records)


def _hop_runtime_from_record(rec: state_mod.HopRecord) -> vpn_mod.HopRuntime:
    from .detect import HopConfig as _HopConfig
    cfg = _HopConfig(
        path=Path(rec.config_path),
        kind=rec.kind,  # type: ignore[arg-type]
        server_host=rec.server_host,
        server_port=0,
        server_ip=rec.server_ip,
    )
    rt = vpn_mod.HopRuntime(k=rec.k, cfg=cfg, iface=rec.iface)
    if rec.ovpn_pidfile:
        rt.pidfile = Path(rec.ovpn_pidfile)
    if rec.ovpn_logfile:
        rt.logfile = Path(rec.ovpn_logfile)
    if rec.ovpn_credfile:
        rt.credfile = Path(rec.ovpn_credfile)
    # No Popen handle — stop_hop will fall back to pidfile-based termination.
    return rt


def _teardown_session(sess: ChainSession) -> None:
    if sess.host is not None:
        try:
            host_mod.restore(sess.host)
        except Exception as e:
            warn(f"host restore raised: {e}")

    for rt in reversed(sess.hops):
        try:
            vpn_mod.stop_hop(rt)
        except Exception as e:
            warn(f"stopping hop {rt.k} raised: {e}")

    if sess.topo is not None:
        for ns in sess.topo.namespaces:
            try:
                vpn_mod.cleanup_ns_resolv(ns)
            except Exception as e:
                warn(f"resolv cleanup for {ns}: {e}")

    try:
        netns_mod.teardown(sess.topo)
    except Exception as e:
        warn(f"netns teardown raised: {e}")

    state_mod.delete_all()
    log("teardown complete")


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    import os
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
