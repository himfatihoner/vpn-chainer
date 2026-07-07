"""Detect VPN config type and extract endpoint host/port."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from pathlib import Path

# Type alias for VPN backend kind. Kept as plain `str` (instead of
# `typing.Literal["wireguard", "openvpn"]`) so the module imports cleanly on
# Python 3.7, where `typing.Literal` doesn't exist. Validation of the actual
# values happens at runtime in `detect()` below.
VpnKind = str


@dataclass
class HopConfig:
    path: Path
    kind: VpnKind
    server_host: str
    server_port: int
    server_ip: str  # resolved IPv4 — used for the per-namespace endpoint route
    needs_credentials: bool = False  # OpenVPN: bare 'auth-user-pass' directive
    username: str | None = None  # filled in by the CLI prompt loop
    password: str | None = None


_WG_HEADER = re.compile(r"^\s*\[Interface\]\s*$", re.MULTILINE)
_WG_PRIVKEY = re.compile(r"^\s*PrivateKey\s*=", re.MULTILINE)
_WG_ENDPOINT = re.compile(r"^\s*Endpoint\s*=\s*(\S+)", re.MULTILINE)

_OVPN_REMOTE = re.compile(
    r"^\s*remote\s+(\S+)(?:\s+(\d+))?", re.MULTILINE
)
_OVPN_AUTH_USER_PASS = re.compile(
    r"^\s*auth-user-pass\s*(\S*)\s*$", re.MULTILINE
)


class DetectError(ValueError):
    """Raised when config type can't be determined or parsed."""


def detect(path: Path, override: VpnKind | None = None) -> HopConfig:
    if not path.is_file():
        raise DetectError(f"config not found: {path}")
    text = path.read_text(errors="replace")

    if override:
        kind: VpnKind = override
    else:
        is_wg = bool(_WG_HEADER.search(text) and _WG_PRIVKEY.search(text))
        is_ovpn = bool(_OVPN_REMOTE.search(text))
        if is_wg and not is_ovpn:
            kind = "wireguard"
        elif is_ovpn and not is_wg:
            kind = "openvpn"
        elif is_wg and is_ovpn:
            raise DetectError(
                f"{path}: file matches both WG and OVPN signatures, pass --type"
            )
        else:
            raise DetectError(
                f"{path}: cannot determine VPN type, pass --type wg|ovpn"
            )

    needs_creds = False
    if kind == "wireguard":
        host, port = _parse_wg_endpoint(text, path)
    else:
        host, port = _parse_ovpn_remote(text, path)
        needs_creds = _ovpn_needs_credentials(text)

    server_ip = _resolve_ipv4(host)
    return HopConfig(
        path=path, kind=kind, server_host=host, server_port=port,
        server_ip=server_ip, needs_credentials=needs_creds,
    )


def _ovpn_needs_credentials(text: str) -> bool:
    """True iff config has a bare 'auth-user-pass' (no path argument)."""
    for m in _OVPN_AUTH_USER_PASS.finditer(text):
        if not m.group(1):  # empty captured arg → bare directive
            return True
    return False


def _parse_wg_endpoint(text: str, path: Path) -> tuple[str, int]:
    m = _WG_ENDPOINT.search(text)
    if not m:
        raise DetectError(f"{path}: no Endpoint = host:port in WireGuard config")
    raw = m.group(1)
    if raw.startswith("["):
        raise DetectError(f"{path}: IPv6 endpoint not supported in v0.1")
    if ":" not in raw:
        raise DetectError(f"{path}: Endpoint missing port: {raw}")
    host, _, port_s = raw.rpartition(":")
    try:
        port = int(port_s)
    except ValueError as e:
        raise DetectError(f"{path}: bad port in Endpoint: {raw}") from e
    return host, port


def _parse_ovpn_remote(text: str, path: Path) -> tuple[str, int]:
    m = _OVPN_REMOTE.search(text)
    if not m:
        raise DetectError(f"{path}: no 'remote ...' line in OpenVPN config")
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else 1194
    return host, port


def _resolve_ipv4(host: str) -> str:
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
    except socket.gaierror as e:
        raise DetectError(f"cannot resolve {host}: {e}") from e
    if not infos:
        raise DetectError(f"cannot resolve {host}")
    return infos[0][4][0]
