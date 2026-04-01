#!/usr/bin/env bash
# ============================================================================
# axios-ioc-scan.sh — Axios npm Supply Chain Compromise (2026-03-31) IOC Scanner
#
# Detects indicators of compromise from the axios@1.14.1 / axios@0.30.4
# supply chain attack that delivered a cross-platform RAT via a malicious
# dependency (plain-crypto-js@4.2.1).
#
# Usage:
#   chmod +x axios-ioc-scan.sh
#   sudo ./axios-ioc-scan.sh
#
# Root is recommended for full filesystem, network, and log visibility.
# Exit code = number of IOCs found (0 = clean).
#
# Covers:
#   - Filesystem artifacts (Linux, macOS, Windows/WSL)
#   - Running processes (RAT, dropper)
#   - Network connections & log hunting (system logs, DNS, web server, IDS)
#   - npm packages, lockfiles, and cache
#   - Docker images built during the exposure window
#   - CrowdSec decisions (if installed)
#   - iptables / nftables / pf firewall rules
#
# Tested on: Ubuntu 22.04/24.04, Debian 12, Fedora 40, Arch, Alpine, macOS 14+
#
# IOC sources:
#   - Wiz Research: https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack
#   - Huntress SOC: https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package
#   - Snyk: https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/
#   - Joe Desimone (Elastic): https://gist.github.com/joe-desimone/36061dabd2bc2513705e0d083a9673e7
#   - StepSecurity, Socket Security, @cyberraiju IOC list
#   - GHSA-fw8c-xr5c-95f9 / MAL-2026-2306
#
# License: MIT
# ============================================================================

set -euo pipefail

# --- C2 indicators (central reference) ---
C2_DOMAIN="sfrclak.com"
C2_IP="142.11.206.73"
C2_PORT="8000"

# Malicious package versions
MAL_AXIOS_V1="1.14.1"
MAL_AXIOS_V2="0.30.4"
MAL_DEP="plain-crypto-js"

# Exposure window (UTC)
WINDOW_START="2026-03-31T00:21:00Z"
WINDOW_END="2026-03-31T03:30:00Z"

# --- Colors & formatting ---
RED='\033[0;31m'
YLW='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
RST='\033[0m'
BOLD='\033[1m'

FINDINGS=0
HOSTNAME_LABEL=$(hostname 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
OS_TYPE=$(uname -s)

header() { echo -e "\n${BOLD}${CYN}[$1]${RST} $2"; }
found()  { echo -e "  ${RED}[!] FOUND:${RST} $1"; FINDINGS=$((FINDINGS + 1)); }
clean()  { echo -e "  ${GRN}[✓]${RST} $1"; }
warn()   { echo -e "  ${YLW}[~]${RST} $1"; }
info()   { echo -e "  ${CYN}[i]${RST} $1"; }

echo -e "${BOLD}============================================================${RST}"
echo -e "${BOLD} Axios Supply Chain IOC Scanner (2026-03-31)${RST}"
echo -e "${BOLD} Host: ${HOSTNAME_LABEL} | OS: ${OS_TYPE} | Scan: ${TIMESTAMP}${RST}"
echo -e "${BOLD}============================================================${RST}"
echo -e " C2 domain: ${C2_DOMAIN} | C2 IP: ${C2_IP}:${C2_PORT}"
echo -e " Malicious versions: axios@${MAL_AXIOS_V1}, axios@${MAL_AXIOS_V2}"
echo -e " Malicious dependency: ${MAL_DEP}@4.2.1"
echo -e " Exposure window: ${WINDOW_START} — ${WINDOW_END}"

# ============================================================================
# 1. FILESYSTEM IOCs — RAT payload artifacts
# ============================================================================
header "1" "Filesystem IOCs — RAT payload artifacts"

check_file_ioc() {
    local path="$1"
    local desc="$2"
    if [[ -e "$path" ]]; then
        found "$path exists ($desc)"
        ls -la "$path" 2>/dev/null
    else
        clean "$path not found"
    fi
}

# Linux
if [[ "$OS_TYPE" == "Linux" ]]; then
    check_file_ioc "/tmp/ld.py" "Linux RAT payload — disguised as system linker"
fi

# macOS
if [[ "$OS_TYPE" == "Darwin" ]]; then
    check_file_ioc "/Library/Caches/com.apple.act.mond" "macOS RAT binary — disguised as Apple cache"

    if grep -rl "com.apple.act.mond" /Library/LaunchDaemons/ 2>/dev/null; then
        found "LaunchDaemon persistence entry referencing com.apple.act.mond"
    else
        clean "No LaunchDaemon persistence for RAT"
    fi
fi

# Windows via WSL
if [[ -d "/mnt/c" ]]; then
    check_file_ioc "/mnt/c/ProgramData/wt.exe" "Windows RAT — PowerShell disguised as Windows Terminal"

    for userdir in /mnt/c/Users/*/AppData/Local/Temp; do
        [[ -d "$userdir" ]] || continue
        check_file_ioc "${userdir}/6202033.vbs" "Windows VBScript dropper"
        check_file_ioc "${userdir}/6202033.ps1" "Windows PowerShell payload"
    done
fi

# ============================================================================
# 2. RUNNING PROCESSES — active RAT indicators
# ============================================================================
header "2" "Running processes — active RAT indicators"

check_process() {
    local pattern="$1"
    local desc="$2"
    if pgrep -f "$pattern" > /dev/null 2>&1; then
        found "$desc"
        ps aux | grep "$pattern" | grep -v grep
    else
        clean "$desc — not running"
    fi
}

if [[ "$OS_TYPE" == "Linux" ]]; then
    check_process "python3.*/tmp/ld.py" "Linux RAT process (python3 /tmp/ld.py)"
fi

if [[ "$OS_TYPE" == "Darwin" ]]; then
    check_process "com\.apple\.act\.mond" "macOS RAT process"
fi

check_process "setup\.js.*plain-crypto" "plain-crypto-js dropper (setup.js)"

# ============================================================================
# 3. NETWORK IOCs — C2 connections & log hunting
# ============================================================================
header "3" "Network IOCs — C2 infrastructure"

# 3a. Active connections
if command -v ss &>/dev/null; then
    if ss -tnp 2>/dev/null | grep -q "$C2_IP"; then
        found "Active connection to C2 IP $C2_IP"
        ss -tnp | grep "$C2_IP"
    else
        clean "No active connections to $C2_IP"
    fi
elif command -v netstat &>/dev/null; then
    if netstat -tnp 2>/dev/null | grep -q "$C2_IP"; then
        found "Active connection to C2 IP $C2_IP"
        netstat -tnp | grep "$C2_IP"
    else
        clean "No active connections to $C2_IP"
    fi
else
    warn "Neither ss nor netstat available — skipping active connection check"
fi

# 3b. DNS resolver logs
DNS_LOGS=(
    "/var/log/pihole/pihole.log"
    "/var/log/pihole.log"
    "/opt/AdGuardHome/data/querylog.json"
    "/var/log/dnsmasq.log"
)

DNS_CHECKED=false
for logfile in "${DNS_LOGS[@]}"; do
    if [[ -f "$logfile" ]]; then
        DNS_CHECKED=true
        if grep -q "$C2_DOMAIN" "$logfile" 2>/dev/null; then
            found "DNS query for $C2_DOMAIN in $logfile"
            grep "$C2_DOMAIN" "$logfile" | tail -5
        else
            clean "No $C2_DOMAIN queries in $logfile"
        fi
    fi
done

if command -v resolvectl &>/dev/null && command -v journalctl &>/dev/null; then
    if journalctl -u systemd-resolved --since "2026-03-30" --until "2026-04-02" 2>/dev/null | grep -q "$C2_DOMAIN"; then
        found "DNS query for $C2_DOMAIN in systemd-resolved journal"
        DNS_CHECKED=true
    fi
fi

if [[ "$DNS_CHECKED" == false ]]; then
    info "No supported DNS logs found — skipping DNS check"
fi

# 3c. Web server / reverse proxy logs
WEB_LOG_DIRS=(
    "/var/log/caddy/"
    "/var/log/nginx/"
    "/var/log/apache2/"
    "/var/log/httpd/"
    "/var/log/traefik/"
)

for logdir in "${WEB_LOG_DIRS[@]}"; do
    if [[ -d "$logdir" ]]; then
        hits=$(grep -rlE "$C2_IP|$C2_DOMAIN" "$logdir" 2>/dev/null || true)
        if [[ -n "$hits" ]]; then
            found "C2 indicator in web server logs: $hits"
            grep -hE "$C2_IP|$C2_DOMAIN" $hits | tail -5
        fi
    fi
done

# 3d. IDS logs (Suricata, Snort)
IDS_LOGS=(
    "/var/log/suricata/eve.json"
    "/var/log/suricata/fast.log"
    "/var/log/snort/alert"
    "/var/log/snort/snort.alert.fast"
)

for logfile in "${IDS_LOGS[@]}"; do
    if [[ -f "$logfile" ]]; then
        if grep -qE "$C2_IP|$C2_DOMAIN" "$logfile" 2>/dev/null; then
            found "C2 indicator in IDS log: $logfile"
            grep -E "$C2_IP|$C2_DOMAIN" "$logfile" | tail -5
        else
            clean "No C2 indicators in $logfile"
        fi
    fi
done

# 3e. System journal (catch-all)
if command -v journalctl &>/dev/null; then
    if journalctl --since "2026-03-30" --until "2026-04-02" 2>/dev/null | grep -qE "$C2_IP|$C2_DOMAIN"; then
        found "C2 indicator in system journal (Mar 30 — Apr 1)"
        journalctl --since "2026-03-30" --until "2026-04-02" | grep -E "$C2_IP|$C2_DOMAIN" | tail -10
    else
        clean "No C2 indicators in system journal for the exposure window"
    fi
fi

# ============================================================================
# 4. NPM / NODE.JS — package-level compromise
# ============================================================================
header "4" "npm / Node.js — malicious package detection"

# 4a. Search node_modules for plain-crypto-js
info "Searching for $MAL_DEP in node_modules (this may take a moment)..."
PLAIN_CRYPTO_HITS=$(find / -maxdepth 8 -type d -name "$MAL_DEP" \
    -path "*/node_modules/*" 2>/dev/null || true)

if [[ -n "$PLAIN_CRYPTO_HITS" ]]; then
    found "$MAL_DEP directory found in node_modules:"
    echo "$PLAIN_CRYPTO_HITS"
else
    clean "No $MAL_DEP directories in node_modules"
fi

# 4b. Search lockfiles for compromised versions
info "Searching lockfiles for axios@${MAL_AXIOS_V1}, axios@${MAL_AXIOS_V2}, ${MAL_DEP}..."
LOCKFILE_PATTERN="axios@${MAL_AXIOS_V1}|axios@${MAL_AXIOS_V2}|${MAL_DEP}"
LOCKFILE_HITS=$(find / -maxdepth 6 \
    \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) \
    -exec grep -lE "$LOCKFILE_PATTERN" {} \; 2>/dev/null || true)

if [[ -n "$LOCKFILE_HITS" ]]; then
    found "Compromised package references in lockfiles:"
    for lf in $LOCKFILE_HITS; do
        echo -e "  ${YLW}---${RST} $lf:"
        grep -nE "$LOCKFILE_PATTERN" "$lf" | head -10
    done
else
    clean "No compromised versions in any lockfiles"
fi

# 4c. Check npm cache
if command -v npm &>/dev/null; then
    NPM_CACHE=$(npm config get cache 2>/dev/null || echo "$HOME/.npm")
    if [[ -d "$NPM_CACHE" ]]; then
        if grep -rq "$MAL_DEP" "$NPM_CACHE" 2>/dev/null; then
            found "$MAL_DEP references in npm cache — run: npm cache clean --force"
        else
            clean "npm cache appears clean"
        fi
    fi
fi

# ============================================================================
# 5. DOCKER — images built during the exposure window
# ============================================================================
header "5" "Docker — images potentially built during exposure window"

if command -v docker &>/dev/null; then
    SUSPECT_IMAGES=$(docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' 2>/dev/null \
        | grep -E "2026-03-31" || true)
    if [[ -n "$SUSPECT_IMAGES" ]]; then
        warn "Docker images created on 2026-03-31 (review if they ran npm install):"
        echo "$SUSPECT_IMAGES"
    else
        clean "No Docker images created during the exposure window"
    fi
else
    info "Docker not installed — skipping"
fi

# ============================================================================
# 6. CROWDSEC — C2 IP in decisions (optional)
# ============================================================================
header "6" "CrowdSec — C2 IP in decisions"

if command -v cscli &>/dev/null; then
    if cscli decisions list 2>/dev/null | grep -q "$C2_IP"; then
        clean "C2 IP $C2_IP is banned in CrowdSec"
    else
        warn "C2 IP $C2_IP is NOT in CrowdSec decisions — consider adding:"
        info "  cscli decisions add --ip $C2_IP --duration 8760h --reason 'Axios supply chain C2'"
    fi
else
    info "CrowdSec not installed — skipping"
fi

# ============================================================================
# 7. FIREWALL — C2 IP block status
# ============================================================================
header "7" "Firewall — C2 IP block status"

FW_CHECKED=false

if command -v iptables &>/dev/null; then
    FW_CHECKED=true
    if iptables -L -n 2>/dev/null | grep -q "$C2_IP"; then
        clean "C2 IP $C2_IP is blocked in iptables"
    else
        warn "C2 IP $C2_IP is NOT blocked in iptables"
        info "  Quick block: iptables -I OUTPUT -d $C2_IP -j DROP"
    fi
fi

if command -v nft &>/dev/null; then
    FW_CHECKED=true
    if nft list ruleset 2>/dev/null | grep -q "$C2_IP"; then
        clean "C2 IP $C2_IP is blocked in nftables"
    else
        warn "C2 IP $C2_IP is NOT blocked in nftables"
    fi
fi

# macOS pf
if [[ "$OS_TYPE" == "Darwin" ]] && command -v pfctl &>/dev/null; then
    FW_CHECKED=true
    if pfctl -sr 2>/dev/null | grep -q "$C2_IP"; then
        clean "C2 IP $C2_IP is blocked in pf"
    else
        warn "C2 IP $C2_IP is NOT blocked in pf"
    fi
fi

if [[ "$FW_CHECKED" == false ]]; then
    info "No supported firewall found — skipping"
fi

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo -e "${BOLD}============================================================${RST}"
if [[ $FINDINGS -gt 0 ]]; then
    echo -e "${RED}${BOLD} SCAN COMPLETE: $FINDINGS IOC(s) DETECTED${RST}"
    echo ""
    echo -e "${RED} This host may be compromised. Immediate actions:${RST}"
    echo -e "  1. Isolate this machine from the network"
    echo -e "  2. Rotate ALL credentials (npm, SSH, cloud keys, API tokens, .env)"
    echo -e "  3. Block C2: ${C2_IP} / ${C2_DOMAIN} at all egress points"
    echo -e "  4. Rebuild from clean image — do NOT attempt to clean in place"
    echo -e "  5. Audit CI/CD pipelines for runs during the exposure window"
else
    echo -e "${GRN}${BOLD} SCAN COMPLETE: No IOCs detected${RST}"
    echo ""
    echo -e "  Preventive recommendations:"
    echo -e "  - Pin axios to 1.14.0 (or 0.30.3 for legacy)"
    echo -e "  - Enforce ${BOLD}npm ci${RST} with committed lockfiles in all CI/CD"
    echo -e "  - Set quarantine: ${BOLD}npm config set min-release-age 3${RST}"
    echo -e "  - Block C2 proactively: ${C2_IP} / ${C2_DOMAIN}"
    echo -e "  - Require OIDC/SLSA provenance for critical dependencies"
fi
echo ""
echo -e " References:"
echo -e "  - GHSA-fw8c-xr5c-95f9 / MAL-2026-2306"
echo -e "  - https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack"
echo -e "  - https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package"
echo -e "${BOLD}============================================================${RST}"
echo -e " Report: ${HOSTNAME_LABEL} | ${TIMESTAMP} | Findings: ${FINDINGS}"
echo -e "${BOLD}============================================================${RST}"

exit $FINDINGS
