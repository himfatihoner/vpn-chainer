#!/usr/bin/env bash
# verify_chain.sh — sanity-check a live vpn-chainer chain.
#
#   sudo ./verify_chain.sh                # standard checks
#   sudo ./verify_chain.sh --kill-test 2  # also bring down hop 2 to prove the
#                                         # chain is real (host should lose
#                                         # internet during the test)
#
# Reads /var/lib/vpnchainer/topology.json (written by vpn_chainer.py up) to
# discover the namespaces. Exits 0 if every check passes, non-zero otherwise.

set -uo pipefail

PERSIST_DIR=/var/lib/vpnchainer
RUN_DIR=/run/vpnchainer
TOPO=$PERSIST_DIR/topology.json
HOST_STATE=$PERSIST_DIR/host_state.json
STATE_DIR=$RUN_DIR  # back-compat for pid/log paths below
PROBE_URL=https://api.ipify.org
PING_TARGET=1.1.1.1

KILL_HOP=
ENCAP=0
PASS=0
FAIL=0
WARN=0

# ─────────────────────────── coloring ───────────────────────────
if [[ -t 1 ]]; then
    C_OK=$'\033[32m'
    C_WARN=$'\033[33m'
    C_FAIL=$'\033[31m'
    C_DIM=$'\033[2m'
    C_BOLD=$'\033[1m'
    C_RST=$'\033[0m'
else
    C_OK=; C_WARN=; C_FAIL=; C_DIM=; C_BOLD=; C_RST=
fi

ok()    { echo "  ${C_OK}✓${C_RST} $*";   PASS=$((PASS+1)); }
warn()  { echo "  ${C_WARN}!${C_RST} $*"; WARN=$((WARN+1)); }
fail()  { echo "  ${C_FAIL}✗${C_RST} $*"; FAIL=$((FAIL+1)); }
info()  { echo "  ${C_DIM}·${C_RST} $*"; }
hdr()   { echo; echo "${C_BOLD}== $* ==${C_RST}"; }

# ─────────────────────────── arg parse ──────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kill-test) KILL_HOP="${2:-}"; shift 2 ;;
        --encap)     ENCAP=1; shift ;;
        -h|--help)
            sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# ─────────────────────────── prelude ────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "this script must run as root (sudo)" >&2
    exit 2
fi

if [[ ! -f $TOPO ]]; then
    echo "${C_FAIL}no chain found at $TOPO — is vpn_chainer.py running?${C_RST}" >&2
    exit 1
fi

# Parse topology — prefer jq, fall back to python.
if command -v jq >/dev/null 2>&1; then
    N_HOPS=$(jq -r '.n_hops' "$TOPO")
    NAMESPACES=( $(jq -r '.namespaces[]' "$TOPO") )
    BASE_PREFIX=$(jq -r '.base_prefix' "$TOPO")
elif command -v python3 >/dev/null 2>&1; then
    eval "$(TOPO="$TOPO" python3 - <<'PY'
import json, os
d = json.load(open(os.environ["TOPO"]))
print(f"N_HOPS={d['n_hops']}")
print("NAMESPACES=( " + " ".join(d["namespaces"]) + " )")
print(f"BASE_PREFIX={d['base_prefix']}")
PY
    )"
else
    echo "need 'jq' or python3 to parse topology.json" >&2
    exit 2
fi

REDIRECT_DONE=false
if [[ -f $HOST_STATE ]]; then
    if grep -q '"redirect_done": true' "$HOST_STATE" 2>/dev/null; then
        REDIRECT_DONE=true
    fi
fi

echo "${C_BOLD}vpn-chainer verification${C_RST}"
echo "  hops     : $N_HOPS  (${NAMESPACES[*]})"
echo "  subnet   : ${BASE_PREFIX}.0.0/16"
echo "  redirect : $REDIRECT_DONE"

# ─────────────────────── 1. namespaces alive ────────────────────
hdr "1. namespaces"
for ns in "${NAMESPACES[@]}"; do
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$ns"; then
        ok "$ns exists"
    else
        fail "$ns missing"
    fi
done

# ─────────────────────── 2. tunnel health ───────────────────────
hdr "2. tunnel interfaces"
declare -a TUN_IFACE_BY_HOP=()
for k in $(seq 1 "$N_HOPS"); do
    ns="${NAMESPACES[$((k-1))]}"
    # Look for wgc<k> (WireGuard) or any tun<n> (OpenVPN) inside the ns.
    iface=""
    if ip netns exec "$ns" ip link show "wgc${k}" &>/dev/null; then
        iface="wgc${k}"
        # Show transfer + handshake age
        hs=$(ip netns exec "$ns" wg show "$iface" latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
        if [[ -n $hs && $hs != 0 ]]; then
            age=$(( $(date +%s) - hs ))
            ok "$ns: WireGuard $iface (last handshake ${age}s ago)"
        else
            fail "$ns: WireGuard $iface (NO handshake)"
        fi
    else
        # OpenVPN tun device
        iface=$(ip netns exec "$ns" ip -o link show type tun 2>/dev/null | awk -F': ' 'NR==1{split($2,a,"@"); print a[1]}')
        if [[ -n $iface ]]; then
            pidfile="$STATE_DIR/ovpn-${k}.pid"
            if [[ -f $pidfile ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
                ok "$ns: OpenVPN $iface (pid $(cat "$pidfile") alive)"
            else
                warn "$ns: OpenVPN $iface (pid file or process missing)"
            fi
        else
            fail "$ns: no tunnel interface (wgc${k} or tunN) found"
        fi
    fi
    TUN_IFACE_BY_HOP[$k]="$iface"
done

# ─────────────────────── 3. per-hop exit IP ─────────────────────
hdr "3. exit IPs (each hop should differ)"
declare -a EXIT_IPS=()
for k in $(seq 1 "$N_HOPS"); do
    ns="${NAMESPACES[$((k-1))]}"
    ip=$(ip netns exec "$ns" curl -fsS --max-time 10 "$PROBE_URL" 2>/dev/null | tr -d '[:space:]')
    if [[ -z $ip ]]; then
        fail "$ns: exit IP probe FAILED (tunnel down?)"
        EXIT_IPS+=("")
        continue
    fi
    EXIT_IPS+=("$ip")
    # Try to enrich with country/org from ipinfo (best-effort, may also fail).
    meta=$(ip netns exec "$ns" curl -fsS --max-time 6 "https://ipinfo.io/${ip}/json" 2>/dev/null \
        | tr -d '\n' | grep -oE '"(country|org|city)":"[^"]*"' | tr '\n' ' ')
    if [[ -n $meta ]]; then
        ok "$ns: $ip   ${C_DIM}${meta}${C_RST}"
    else
        ok "$ns: $ip"
    fi
done

# ─────────────────────── 4. exit-IP uniqueness ──────────────────
# Uniqueness + redirect coherence.
hdr "4. exit-IP uniqueness"
seen=()
unique=true
for ip in "${EXIT_IPS[@]}"; do
    [[ -z $ip ]] && continue
    for prev in "${seen[@]:-}"; do
        if [[ $prev == "$ip" ]]; then
            unique=false; break
        fi
    done
    seen+=("$ip")
done
if $unique && [[ ${#EXIT_IPS[@]} -gt 0 ]]; then
    ok "all hops show distinct public IPs"
else
    fail "duplicate IPs found — chain is collapsing somewhere"
fi

if $REDIRECT_DONE; then
    host_ip=$(curl -fsS --max-time 10 "$PROBE_URL" 2>/dev/null | tr -d '[:space:]')
    last_ip="${EXIT_IPS[$((N_HOPS-1))]:-}"
    if [[ -n $host_ip && -n $last_ip ]]; then
        if [[ $host_ip == "$last_ip" ]]; then
            ok "host exit IP ($host_ip) == last hop"
        else
            fail "host exit IP ($host_ip) != last hop ($last_ip)"
        fi
    else
        warn "could not compare host vs last-hop IP"
    fi
else
    info "host default route not redirected (--no-redirect mode); skipping host-IP check"
fi

# ─────────────────────── 5. latency layering ────────────────────
hdr "5. latency layering (each hop should add RTT)"
declare -a RTTS=()
for k in $(seq 1 "$N_HOPS"); do
    ns="${NAMESPACES[$((k-1))]}"
    rtt=$(ip netns exec "$ns" ping -c 3 -W 3 -q -n "$PING_TARGET" 2>/dev/null \
        | awk -F/ '/^rtt/ {print $5}')
    if [[ -z $rtt ]]; then
        warn "$ns: ping to $PING_TARGET failed"
        RTTS+=("")
    else
        RTTS+=("$rtt")
        info "$ns: avg ${rtt} ms"
    fi
done
# Check monotonic-ish growth (allow noise: each hop must be > prev - 5ms).
mono=true
prev=0
for r in "${RTTS[@]}"; do
    [[ -z $r ]] && continue
    if (( $(awk "BEGIN{print ($r + 5 < $prev)?1:0}") )); then
        mono=false; break
    fi
    prev="$r"
done
if $mono; then
    ok "RTT increases (or holds) with each hop"
else
    warn "RTT decreased between hops — unusual; provider routing or chain bypass"
fi

# ─────────────────────── 6. lockdown / kill-switch ──────────────
hdr "6. lockdown (default-DROP firewall in each ns)"
for k in $(seq 1 "$N_HOPS"); do
    ns="${NAMESPACES[$((k-1))]}"
    pols=$(ip netns exec "$ns" iptables -S 2>/dev/null \
        | awk '/^-P/ {print $2"="$3}' | tr '\n' ' ')
    if [[ "$pols" == *"INPUT=DROP"* && "$pols" == *"OUTPUT=DROP"* && "$pols" == *"FORWARD=DROP"* ]]; then
        ok "$ns: filter policies all DROP"
    else
        fail "$ns: policies not locked down ($pols)"
    fi
done

# ─────────────────────── 7. routing closed-loop ─────────────────
# Synthetic leak attempt: try forwarding an arbitrary packet from inside ns_k
# OUT the upstream veth toward a public destination. With the lockdown's
# FORWARD policy DROP this MUST fail (the only allowed FORWARD path is
# downstream→tunnel→downstream). socat + iptables counter trick: ask the
# kernel `ip route get` whether the upstream veth even appears as a candidate
# oif for a public IP — if it does, that's a routing leak; if not, locked down.
hdr "7. routing closed-loop (no path leaks past the tunnel)"
for k in $(seq 1 "$N_HOPS"); do
    ns="${NAMESPACES[$((k-1))]}"
    out=$(ip netns exec "$ns" ip -4 route get 1.1.1.1 2>&1 | head -1)
    iface=$(echo "$out" | sed -nE 's/.* dev ([^ ]+).*/\1/p')
    if [[ $iface == wgc* || $iface == tun* ]]; then
        ok "$ns: 1.1.1.1 routed via tunnel iface ($iface)"
    else
        fail "$ns: 1.1.1.1 routed via $iface — should be the tunnel"
    fi
done

# ─────────────────────── 8. NAT counters ────────────────────────
hdr "8. MASQUERADE packet counters per ns"
for k in $(seq 1 "$N_HOPS"); do
    ns="${NAMESPACES[$((k-1))]}"
    iface="${TUN_IFACE_BY_HOP[$k]:-}"
    [[ -z $iface ]] && continue
    pkts=$(ip netns exec "$ns" iptables -t nat -L POSTROUTING -nvx 2>/dev/null \
        | awk -v ifc="$iface" '$0 ~ ifc && /MASQUERADE/ {print $1; exit}')
    if [[ -n $pkts && $pkts -gt 0 ]]; then
        ok "$ns: $pkts packets MASQUERADE'd out $iface"
    elif [[ -n $pkts ]]; then
        warn "$ns: 0 packets through MASQUERADE (no traffic yet?)"
    else
        warn "$ns: MASQUERADE rule on $iface not found"
    fi
done

# ────── 9. wire isolation: host's NIC must talk ONLY to hop1's IP ──────
hdr "9. wire isolation (anonymity test — sniff host's physical NIC)"
HOPS_FILE=$PERSIST_DIR/hops.json
if ! command -v tcpdump >/dev/null 2>&1; then
    warn "tcpdump not installed — skipping wire isolation test"
elif [[ ! -f $HOPS_FILE ]]; then
    warn "no hops.json — skipping wire isolation test"
elif [[ ! -f $HOST_STATE ]]; then
    warn "no host_state.json — skipping wire isolation test"
else
    # NIC + per-hop server IPs
    if command -v jq >/dev/null 2>&1; then
        NIC=$(jq -r '.orig_default_iface' "$HOST_STATE")
        SERVER_IPS=( $(jq -r '.[].server_ip' "$HOPS_FILE") )
    else
        NIC=$(HS="$HOST_STATE" python3 -c 'import json,os;print(json.load(open(os.environ["HS"]))["orig_default_iface"])')
        SERVER_IPS=( $(HF="$HOPS_FILE" python3 -c 'import json,os;[print(h["server_ip"]) for h in json.load(open(os.environ["HF"]))]') )
    fi
    info "physical NIC: $NIC   |   sole expected peer: ${SERVER_IPS[0]} (hop 1)"

    # Generate continuous chain traffic so the sniffer has something to match.
    ( while sleep 1; do
          curl -s --max-time 4 https://api.ipify.org -o /dev/null
      done ) &
    GEN_PID=$!

    # Positive control: confirm the chain IS active (hop 1 IP visible).
    out=$(timeout 6 tcpdump -ni "$NIC" -c 1 -n -q "host ${SERVER_IPS[0]}" 2>/dev/null \
          | grep -cE '^[0-9]{2}:[0-9]{2}:[0-9]{2}')
    if [[ ${out:-0} -gt 0 ]]; then
        ok "host ↔ hop 1 (${SERVER_IPS[0]}) seen on $NIC (positive control)"
    else
        warn "no host ↔ hop 1 traffic seen — chain may be idle, isolation tests below are inconclusive"
    fi

    # Negative tests: every hop K≥2 server IP must be silent on the NIC.
    for k in $(seq 2 "$N_HOPS"); do
        target="${SERVER_IPS[$((k-1))]}"
        out=$(timeout 8 tcpdump -ni "$NIC" -c 1 -n -q "host $target" 2>/dev/null \
              | grep -cE '^[0-9]{2}:[0-9]{2}:[0-9]{2}')
        if [[ ${out:-0} -gt 0 ]]; then
            fail "LEAK: host's NIC sent/received packets to hop $k ($target) — anonymity broken"
        else
            ok "no host ↔ hop $k ($target) traffic on $NIC (8 s window)"
        fi
    done

    # Cleanup
    kill "$GEN_PID" 2>/dev/null
    wait "$GEN_PID" 2>/dev/null

    # Static check: confirm DROP rules are in iptables for non-hop1 IPs.
    for k in $(seq 2 "$N_HOPS"); do
        target="${SERVER_IPS[$((k-1))]}"
        if iptables -C OUTPUT -d "$target" -o "$NIC" -j DROP 2>/dev/null \
        && iptables -C FORWARD -d "$target" -o "$NIC" -j DROP 2>/dev/null; then
            ok "iptables DROP rules in place for hop $k ($target → $NIC)"
        else
            fail "iptables DROP rules MISSING for hop $k ($target) — install via 'up'"
        fi
    done
fi

# ─────────────────────── 10. optional encap peek ────────────────
if [[ $ENCAP -eq 1 ]]; then
    hdr "10. encapsulation snapshot (5 packets each)"
    for k in $(seq 1 "$N_HOPS"); do
        ns="${NAMESPACES[$((k-1))]}"
        veth_inner="vpnc${k}i"
        echo "  ${C_DIM}-- $ns: $veth_inner (carrier traffic) --${C_RST}"
        ip netns exec "$ns" timeout 4 tcpdump -ni "$veth_inner" -c 5 -nn 2>/dev/null \
            | sed 's/^/      /'
    done
fi

# ─────────────────────── 11. optional kill test ─────────────────
if [[ -n $KILL_HOP ]]; then
    if ! [[ $KILL_HOP =~ ^[0-9]+$ ]] || (( KILL_HOP < 1 || KILL_HOP > N_HOPS )); then
        fail "--kill-test argument must be 1..$N_HOPS, got: $KILL_HOP"
    else
        hdr "11. kill-test: take down hop $KILL_HOP and check host loses internet"
        ns="${NAMESPACES[$((KILL_HOP-1))]}"
        iface="${TUN_IFACE_BY_HOP[$KILL_HOP]:-}"
        if [[ $iface == wgc* ]]; then
            ip netns exec "$ns" ip link set "$iface" down
            sleep 2
            if curl -fsS --max-time 4 "$PROBE_URL" >/dev/null 2>&1; then
                fail "host still has internet — chain is BYPASSING hop $KILL_HOP"
            else
                ok "host lost internet (expected) — hop $KILL_HOP is real in the chain"
            fi
            ip netns exec "$ns" ip link set "$iface" up
            info "restored $iface — wait a few seconds for handshake/conntrack"
        else
            pidfile="$STATE_DIR/ovpn-${KILL_HOP}.pid"
            if [[ -f $pidfile ]]; then
                pid=$(cat "$pidfile")
                kill -STOP "$pid" 2>/dev/null
                sleep 2
                if curl -fsS --max-time 4 "$PROBE_URL" >/dev/null 2>&1; then
                    fail "host still has internet — chain is BYPASSING hop $KILL_HOP"
                else
                    ok "host lost internet (expected) — hop $KILL_HOP is real in the chain"
                fi
                kill -CONT "$pid" 2>/dev/null
                info "restored OpenVPN process — give it a few seconds"
            else
                warn "no pidfile for hop $KILL_HOP, can't kill-test"
            fi
        fi
    fi
fi

# ─────────────────────── summary ────────────────────────────────
hdr "summary"
echo "  ${C_OK}pass:${C_RST} $PASS    ${C_WARN}warn:${C_RST} $WARN    ${C_FAIL}fail:${C_RST} $FAIL"
if (( FAIL > 0 )); then
    exit 1
fi
exit 0
