#!/usr/bin/env bash
# vpn-chainer one-line installer.
#
#   sudo bash install.sh                                # local checkout
#   curl -fsSL https://.../install.sh | sudo bash       # remote
#
# Ends up with:
#   /usr/local/share/vpn-chainer/      (project files)
#   /usr/local/bin/vpn-chainer         (wrapper, on PATH)
#
# After install:  vpn-chainer status  ·  sudo vpn-chainer up -c …

set -euo pipefail

# ─────────────────────────── configuration ──────────────────────────────
INSTALL_DIR="/usr/local/share/vpn-chainer"
WRAPPER_PATH="/usr/local/bin/vpn-chainer"
LOG_FILE="/tmp/vpn-chainer-install.log"

# Override these via env vars when piping curl|bash to install from a fork:
GITHUB_USER="${VPNCHAINER_GITHUB_USER:-himfatihoner}"
GITHUB_REPO="${VPNCHAINER_GITHUB_REPO:-vpn-chainer}"
GITHUB_REF="${VPNCHAINER_GITHUB_REF:-main}"

# ─────────────────────────── colours ────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    MAG=$'\033[35m'
    CYAN=$'\033[36m'
    BCYAN=$'\033[96m'
    BMAG=$'\033[95m'
    BYEL=$'\033[93m'
    RST=$'\033[0m'
else
    BOLD= DIM= RED= GREEN= YELLOW= BLUE= MAG= CYAN= BCYAN= BMAG= BYEL= RST=
fi

# ─────────────────────────── step helpers ───────────────────────────────
STEP_START_NS=0
step_start() {
    STEP_START_NS=$(date +%s%N 2>/dev/null || echo 0)
    printf "  ${DIM}[ ]${RST} %s${DIM}…${RST}" "$1" >&2
}

_elapsed() {
    if [ "$STEP_START_NS" = 0 ]; then
        printf ""
        return
    fi
    local now=$(date +%s%N 2>/dev/null || echo 0)
    local diff_ns=$((now - STEP_START_NS))
    local sec=$((diff_ns / 1000000000))
    local frac=$(( (diff_ns / 100000000) % 10 ))
    printf " ${DIM}%d.%ds${RST}" "$sec" "$frac"
}

step_ok() {
    printf "\r\033[K  ${GREEN}${BOLD}[✓]${RST} %s$(_elapsed)\n" "$1" >&2
}

step_skip() {
    printf "\r\033[K  ${DIM}[-]${RST} ${DIM}%s (skipped)${RST}\n" "$1" >&2
}

step_fail() {
    printf "\r\033[K  ${RED}${BOLD}[✗]${RST} %s\n" "$1" >&2
    if [ -n "${2:-}" ]; then
        printf "      ${RED}%s${RST}\n" "$2" >&2
    fi
    if [ -f "$LOG_FILE" ]; then
        printf "      ${DIM}see %s for details${RST}\n" "$LOG_FILE" >&2
    fi
    exit 1
}

note() {
    printf "  ${DIM}·${RST} %s\n" "$1" >&2
}

# ─────────────────────────── banner ─────────────────────────────────────
print_banner() {
    cat <<EOF

  ${BOLD}${BCYAN}__   _____  _  _    ___ _         _              ${RST}
  ${BOLD}${CYAN}\\ \\ / / _ \\| \\| |  / __| |_  __ _(_)_ _  ___ _ _ ${RST}
  ${BOLD}${BMAG} \\ V /|  _/| .\` | | (__| ' \\/ _\` | | ' \\/ -_) '_|${RST}
  ${BOLD}${MAG}  \\_/ |_|  |_|\\_|  \\___|_||_\\__,_|_|_||_\\___|_|  ${RST}

  ${BOLD}${BCYAN}╶╶ installer ╶╶${RST}   ${DIM}v0.1.0 · multi-hop VPN orchestrator${RST}

EOF
}

# ─────────────────────────── pre-flight ─────────────────────────────────
preflight() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        step_fail "Root required" "Re-run with: sudo bash $0   (or pipe to: curl ... | sudo bash)"
    fi

    if [ "$(uname -s)" != "Linux" ]; then
        step_fail "Linux only" "vpn-chainer relies on net namespaces; macOS/BSD not supported"
    fi

    if ! command -v curl >/dev/null 2>&1; then
        step_fail "'curl' is required for installation" \
            "Install it first: apt install curl  /  dnf install curl  /  pacman -S curl"
    fi
}

# ─────────────────────────── distro detection ───────────────────────────
detect_distro() {
    step_start "Detecting Linux distribution"
    if [ ! -f /etc/os-release ]; then
        step_fail "/etc/os-release not found"
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_LIKE="${ID_LIKE:-}"
    DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
    step_ok "Detected: ${BOLD}${DISTRO_NAME}${RST}"
}

# ─────────────────────────── package manager ────────────────────────────
choose_pm() {
    step_start "Selecting package manager"
    case "$DISTRO_ID $DISTRO_LIKE" in
        *debian*|*ubuntu*|kali*|*raspbian*|*linuxmint*|*pop*|*elementary*)
            PM="apt"
            PM_UPDATE="apt-get update -qq"
            PM_INSTALL="DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends"
            PKGS="python3 iproute2 iptables openvpn wireguard-tools traceroute curl jq tcpdump procps iputils-ping"
            ;;
        *fedora*|*rhel*|*centos*|*rocky*|*almalinux*|*amzn*)
            PM="dnf"
            if ! command -v dnf >/dev/null 2>&1; then PM_BIN="yum"; else PM_BIN="dnf"; fi
            PM_UPDATE=""
            PM_INSTALL="$PM_BIN install -q -y"
            PKGS="python3 iproute iptables openvpn wireguard-tools traceroute curl jq tcpdump procps-ng iputils"
            ;;
        *arch*|*manjaro*|*endeavour*|*garuda*)
            PM="pacman"
            PM_UPDATE="pacman -Sy --noconfirm"
            PM_INSTALL="pacman -S --needed --noconfirm"
            PKGS="python iproute2 iptables openvpn wireguard-tools traceroute curl jq tcpdump procps-ng iputils"
            ;;
        *alpine*)
            PM="apk"
            PM_UPDATE="apk update -q"
            PM_INSTALL="apk add --no-cache"
            PKGS="python3 iproute2 iptables openvpn wireguard-tools-wg traceroute curl jq tcpdump procps iputils"
            ;;
        *suse*|*opensuse*)
            PM="zypper"
            PM_UPDATE=""
            PM_INSTALL="zypper install -y --no-recommends"
            PKGS="python3 iproute2 iptables openvpn wireguard-tools traceroute curl jq tcpdump procps iputils"
            ;;
        *)
            step_fail "Unsupported distro: $DISTRO_ID" \
                "Open an issue: https://github.com/${GITHUB_USER}/${GITHUB_REPO}/issues"
            ;;
    esac
    step_ok "Package manager: ${BOLD}${PM}${RST}"
}

# ─────────────────────────── install dependencies ───────────────────────
install_deps() {
    : > "$LOG_FILE"

    if [ -n "$PM_UPDATE" ]; then
        step_start "Updating package index"
        if ! eval "$PM_UPDATE" >>"$LOG_FILE" 2>&1; then
            step_fail "Package index update failed"
        fi
        step_ok "Package index updated"
    fi

    step_start "Installing dependencies (${PKGS// /, })"
    if ! eval "$PM_INSTALL $PKGS" >>"$LOG_FILE" 2>&1; then
        step_fail "Dependency installation failed"
    fi
    step_ok "Dependencies installed"
}

# ─────────────────────────── source acquisition ─────────────────────────
acquire_source() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"

    # Local checkout?
    if [ -n "$script_dir" ] \
        && [ -f "$script_dir/vpn_chainer.py" ] \
        && [ -d "$script_dir/chainer" ]; then
        step_start "Using local source: $script_dir"
        SRC_DIR="$script_dir"
        SRC_TEMP=""
        step_ok "Local source: $script_dir"
        return
    fi

    # Remote: fetch from GitHub.
    step_start "Downloading vpn-chainer (${GITHUB_USER}/${GITHUB_REPO}@${GITHUB_REF})"
    SRC_TEMP="$(mktemp -d)"
    SRC_DIR="$SRC_TEMP"
    local url="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/archive/refs/heads/${GITHUB_REF}.tar.gz"
    if ! curl -fsSL "$url" 2>>"$LOG_FILE" | tar -xz -C "$SRC_TEMP" --strip-components=1 2>>"$LOG_FILE"; then
        # Fall back to tag-as-ref
        url="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/archive/refs/tags/${GITHUB_REF}.tar.gz"
        if ! curl -fsSL "$url" 2>>"$LOG_FILE" | tar -xz -C "$SRC_TEMP" --strip-components=1 2>>"$LOG_FILE"; then
            step_fail "Download failed" \
                "Check that ${GITHUB_USER}/${GITHUB_REPO}@${GITHUB_REF} exists and is public."
        fi
    fi
    step_ok "Downloaded source"
}

# ─────────────────────────── place files ────────────────────────────────
install_files() {
    step_start "Installing to $INSTALL_DIR"
    rm -rf "${INSTALL_DIR:?}"  # safety: not 'rm -rf $UNSET'
    mkdir -p "$INSTALL_DIR"

    cp -r "$SRC_DIR/chainer" "$INSTALL_DIR/"
    cp "$SRC_DIR/vpn_chainer.py" "$INSTALL_DIR/"
    [ -f "$SRC_DIR/verify_chain.sh" ] && cp "$SRC_DIR/verify_chain.sh" "$INSTALL_DIR/"
    [ -f "$SRC_DIR/uninstall.sh"   ] && cp "$SRC_DIR/uninstall.sh"   "$INSTALL_DIR/"
    [ -d "$SRC_DIR/examples"       ] && cp -r "$SRC_DIR/examples"   "$INSTALL_DIR/"

    chmod +x "$INSTALL_DIR/vpn_chainer.py"
    [ -f "$INSTALL_DIR/verify_chain.sh" ] && chmod +x "$INSTALL_DIR/verify_chain.sh"
    [ -f "$INSTALL_DIR/uninstall.sh"   ] && chmod +x "$INSTALL_DIR/uninstall.sh"

    # Strip any stray bytecode.
    find "$INSTALL_DIR" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
    step_ok "Files installed: $INSTALL_DIR"
}

create_wrapper() {
    step_start "Creating wrapper at $WRAPPER_PATH"
    cat > "$WRAPPER_PATH" <<'WRAPPER_EOF'
#!/bin/sh
# vpn-chainer wrapper — forwards every arg to the actual entry point.
exec /usr/local/share/vpn-chainer/vpn_chainer.py "$@"
WRAPPER_EOF
    chmod +x "$WRAPPER_PATH"
    step_ok "Wrapper installed: $WRAPPER_PATH"
}

# ─────────────────────────── post-checks ────────────────────────────────
verify_install() {
    step_start "Verifying installation"
    if ! "$WRAPPER_PATH" --help >/dev/null 2>&1; then
        step_fail "Verification failed — wrapper does not run"
    fi
    step_ok "Verified: 'vpn-chainer --help' works"

    # Is /usr/local/bin actually on PATH?
    case ":$PATH:" in
        *:/usr/local/bin:*) PATH_OK=yes ;;
        *) PATH_OK=no ;;
    esac
    if [ "$PATH_OK" != yes ]; then
        note "${YELLOW}/usr/local/bin is not on your PATH.${RST}"
        note "Add this line to your shell rc (~/.bashrc / ~/.zshrc):"
        note "    ${BOLD}export PATH=\"/usr/local/bin:\$PATH\"${RST}"
    fi

    # Tooling sanity.
    for cmd in ip iptables openvpn wg; do
        if command -v "$cmd" >/dev/null 2>&1; then
            note "${GREEN}✓${RST} $cmd: $(command -v "$cmd")"
        else
            note "${YELLOW}!${RST} $cmd not found in PATH (chain will fail without it)"
        fi
    done
}

# ─────────────────────────── teardown ───────────────────────────────────
cleanup() {
    [ -n "${SRC_TEMP:-}" ] && [ -d "$SRC_TEMP" ] && rm -rf "$SRC_TEMP"
}
trap cleanup EXIT

# ─────────────────────────── done banner ────────────────────────────────
print_done() {
    cat <<EOF

  ${GREEN}${BOLD}╭──────────────────────────────────────────────────────╮${RST}
  ${GREEN}${BOLD}│  ✓  vpn-chainer installed successfully               │${RST}
  ${GREEN}${BOLD}╰──────────────────────────────────────────────────────╯${RST}

  ${BOLD}Try it:${RST}
    ${BCYAN}vpn-chainer --help${RST}                   ${DIM}# any user${RST}
    ${BCYAN}vpn-chainer status${RST}                   ${DIM}# any user${RST}
    ${BCYAN}sudo vpn-chainer up -c hop1.conf -c hop2.conf${RST}
    ${BCYAN}sudo vpn-chainer down${RST}

  ${BOLD}Verify a live chain:${RST}
    ${BCYAN}sudo $INSTALL_DIR/verify_chain.sh${RST}

  ${BOLD}Uninstall:${RST}
    ${BCYAN}sudo $INSTALL_DIR/uninstall.sh${RST}

  ${DIM}install log: $LOG_FILE${RST}

EOF
}

# ─────────────────────────── main ───────────────────────────────────────
main() {
    print_banner
    preflight
    detect_distro
    choose_pm
    install_deps
    acquire_source
    install_files
    create_wrapper
    verify_install
    print_done
}

main "$@"
