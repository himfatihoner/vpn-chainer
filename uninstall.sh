#!/usr/bin/env bash
# vpn-chainer uninstaller — removes everything install.sh added.
#
#   sudo /usr/local/share/vpn-chainer/uninstall.sh
#
# Does NOT remove distro packages (python3, openvpn, wireguard-tools, etc.) —
# those are usually shared with other tools. If you really want them gone,
# use your package manager manually after this script finishes.

set -uo pipefail   # not -e: each step continues on partial state

INSTALL_DIR="/usr/local/share/vpn-chainer"
WRAPPER_PATH="/usr/local/bin/vpn-chainer"
PERSIST_DIR="/var/lib/vpnchainer"
RUN_DIR="/run/vpnchainer"

# ─────────────────────────── colours ────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'
    CYAN=$'\033[36m'; BCYAN=$'\033[96m'; BMAG=$'\033[95m'; MAG=$'\033[35m'
    RST=$'\033[0m'
else
    BOLD= DIM= RED= GREEN= YELLOW= CYAN= BCYAN= BMAG= MAG= RST=
fi

step_start() { printf "  ${DIM}[ ]${RST} %s${DIM}…${RST}" "$1" >&2; }
step_ok()    { printf "\r\033[K  ${GREEN}${BOLD}[✓]${RST} %s\n" "$1" >&2; }
step_skip()  { printf "\r\033[K  ${DIM}[-]${RST} ${DIM}%s (already gone)${RST}\n" "$1" >&2; }
step_warn()  { printf "\r\033[K  ${YELLOW}${BOLD}[!]${RST} %s\n" "$1" >&2; }

# ─────────────────────────── banner ─────────────────────────────────────
cat <<EOF

  ${BOLD}${BCYAN}__   _____  _  _    ___ _         _              ${RST}
  ${BOLD}${CYAN}\\ \\ / / _ \\| \\| |  / __| |_  __ _(_)_ _  ___ _ _ ${RST}
  ${BOLD}${BMAG} \\ V /|  _/| .\` | | (__| ' \\/ _\` | | ' \\/ -_) '_|${RST}
  ${BOLD}${MAG}  \\_/ |_|  |_|\\_|  \\___|_||_\\__,_|_|_||_\\___|_|  ${RST}

  ${BOLD}${RED}╶╶ uninstaller ╶╶${RST}

EOF

# ─────────────────────────── pre-flight ─────────────────────────────────
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    printf "  ${RED}${BOLD}[✗]${RST} Root required — re-run with sudo\n" >&2
    exit 1
fi

# ─────────────────────────── 1. tear down any active chain ──────────────
if [ -x "$WRAPPER_PATH" ] && [ -f "$PERSIST_DIR/chain.json" ]; then
    step_start "Stopping active chain"
    if "$WRAPPER_PATH" down >/dev/null 2>&1; then
        step_ok "Active chain stopped"
    else
        step_warn "Could not run 'vpn-chainer down' cleanly — falling back to recover"
        "$WRAPPER_PATH" recover -y >/dev/null 2>&1 || true
    fi
elif [ -f "$PERSIST_DIR/chain.json" ]; then
    step_warn "State on disk but wrapper missing — manual recovery may be needed"
else
    step_skip "No active chain"
fi

# ─────────────────────────── 2. remove wrapper ──────────────────────────
if [ -e "$WRAPPER_PATH" ] || [ -L "$WRAPPER_PATH" ]; then
    step_start "Removing $WRAPPER_PATH"
    rm -f "$WRAPPER_PATH"
    step_ok "Removed $WRAPPER_PATH"
else
    step_skip "$WRAPPER_PATH"
fi

# ─────────────────────────── 3. remove install dir ──────────────────────
if [ -d "$INSTALL_DIR" ]; then
    step_start "Removing $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
    step_ok "Removed $INSTALL_DIR"
else
    step_skip "$INSTALL_DIR"
fi

# ─────────────────────────── 4. remove persistent state ─────────────────
if [ -d "$PERSIST_DIR" ]; then
    step_start "Removing persistent state $PERSIST_DIR"
    rm -rf "$PERSIST_DIR"
    step_ok "Removed $PERSIST_DIR"
else
    step_skip "$PERSIST_DIR"
fi

# ─────────────────────────── 5. remove ephemeral state ──────────────────
if [ -d "$RUN_DIR" ]; then
    step_start "Removing ephemeral state $RUN_DIR"
    rm -rf "$RUN_DIR"
    step_ok "Removed $RUN_DIR"
else
    step_skip "$RUN_DIR"
fi

# ─────────────────────────── 6. sanity sweep for orphans ────────────────
ORPHAN_NS=$(ip netns list 2>/dev/null | awk '/^vpnchain_ns/ {print $1}' || true)
if [ -n "$ORPHAN_NS" ]; then
    step_start "Cleaning orphan namespaces"
    for ns in $ORPHAN_NS; do ip netns del "$ns" 2>/dev/null || true; done
    step_ok "Orphan namespaces removed"
fi

ORPHAN_VETHS=$(ip -br link 2>/dev/null | awk '/^vpnc[0-9]+o|^vpncIo/ {split($1,a,"@"); print a[1]}' || true)
if [ -n "$ORPHAN_VETHS" ]; then
    step_start "Cleaning orphan veth interfaces"
    for v in $ORPHAN_VETHS; do ip link del "$v" 2>/dev/null || true; done
    step_ok "Orphan veth interfaces removed"
fi

# ─────────────────────────── done ───────────────────────────────────────
cat <<EOF

  ${GREEN}${BOLD}╭──────────────────────────────────────────────────────╮${RST}
  ${GREEN}${BOLD}│  ✓  vpn-chainer uninstalled                          │${RST}
  ${GREEN}${BOLD}╰──────────────────────────────────────────────────────╯${RST}

  ${DIM}Distro packages (python3, openvpn, wireguard-tools, etc.) are left
  intact. Remove them manually if you want:${RST}

    ${BCYAN}# Debian/Ubuntu/Kali${RST}
    sudo apt purge openvpn wireguard-tools

    ${BCYAN}# Fedora/RHEL${RST}
    sudo dnf remove openvpn wireguard-tools

EOF
