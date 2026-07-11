#!/usr/bin/env bash
#
# VPS Security Audit Tool
# Fork of https://github.com/vernu/vps-audit (MIT) — maintained by mylesagnew.
#
# Hardened revision. Fixes applied vs. upstream:
#   #1 journalctl failed-login check now actually executes (was a literal filename)
#   #2 iptables/nftables firewall check verifies policy/rules (no longer always PASS)
#   #3 SUID check: -xdev + package-baseline verification (no blanket path whitelist)
#   #4 Port check parses bind address to separate public from loopback
#   #5 Sudo logging: syslog treated as the secure default (no false FAIL)
#   #6 Password policy: comment-aware, >=12, checks pwquality.conf.d + PAM
#   #7 SSH parsed from `sshd -T` effective config (not brittle grep)
#   #8 Exit code + --json output so it can gate a CI/CD pipeline
#
set -uo pipefail
umask 077

# ---------------------------------------------------------------------------
# Argument parsing (#8)
# ---------------------------------------------------------------------------
JSON_OUTPUT=false
STRICT=false
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="vps-audit-report-${TIMESTAMP}.txt"

usage() {
    cat <<'EOF'
VPS Security Audit Tool

Usage: vps-audit.sh [options]

Options:
  --json            Emit machine-readable JSON to stdout (suppresses colour UI)
  --strict          Exit non-zero on WARN as well as FAIL (default: FAIL only)
  -o, --output FILE Write the text report to FILE (default: vps-audit-report-<ts>.txt)
  -h, --help        Show this help and exit

Exit codes:
  0  no FAIL findings (and, unless --strict, WARN allowed)
  1  one or more FAIL findings (or any WARN when --strict)
  2  usage error
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --json) JSON_OUTPUT=true ;;
        --strict) STRICT=true ;;
        -o | --output)
            shift
            [ $# -gt 0 ] || {
                echo "error: --output needs an argument" >&2
                exit 2
            }
            REPORT_FILE="$1"
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Colours (disabled when not a TTY or in JSON mode)
# ---------------------------------------------------------------------------
if [ -t 1 ] && ! $JSON_OUTPUT; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GRAY='\033[0;90m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    GREEN=''
    RED=''
    YELLOW=''
    GRAY=''
    BLUE=''
    BOLD=''
    NC=''
fi

# say(): human console output, suppressed in JSON mode
say() { $JSON_OUTPUT || echo -e "$1"; }

# ---------------------------------------------------------------------------
# Result tracking (#8)
# ---------------------------------------------------------------------------
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
JSON_ITEMS=()

json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/ }
    s=${s//$'\t'/ }
    printf '%s' "$s"
}

print_header() {
    local header="$1"
    say "\n${BLUE}${BOLD}$header${NC}"
    {
        echo -e "\n$header"
        echo "================================"
    } >>"$REPORT_FILE"
}

print_info() {
    local label="$1" value="$2"
    say "${BOLD}$label:${NC} $value"
    echo "$label: $value" >>"$REPORT_FILE"
}

check_security() {
    local test_name="$1" status="$2" message="$3"
    case $status in
        PASS)
            PASS_COUNT=$((PASS_COUNT + 1))
            say "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
            ;;
        WARN)
            WARN_COUNT=$((WARN_COUNT + 1))
            say "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
            ;;
        FAIL)
            FAIL_COUNT=$((FAIL_COUNT + 1))
            say "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            ;;
    esac
    {
        echo "[$status] $test_name - $message"
        echo ""
    } >>"$REPORT_FILE"
    JSON_ITEMS+=("{\"test\":\"$(json_escape "$test_name")\",\"status\":\"$status\",\"message\":\"$(json_escape "$message")\"}")
}

# ---------------------------------------------------------------------------
# Report header
# ---------------------------------------------------------------------------
say "${BLUE}${BOLD}VPS Security Audit Tool${NC}"
say "${GRAY}https://github.com/mylesagnew/vps-audit${NC}"
say "${GRAY}Starting audit at $(date)${NC}\n"

{
    echo "VPS Security Audit Tool"
    echo "https://github.com/mylesagnew/vps-audit"
    echo "Starting audit at $(date)"
    echo "================================"
} >"$REPORT_FILE"

# ---------------------------------------------------------------------------
# System Information
# ---------------------------------------------------------------------------
print_header "System Information"

OS_INFO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
KERNEL_VERSION=$(uname -r)
UPTIME=$(uptime -p 2>/dev/null)
UPTIME_SINCE=$(uptime -s 2>/dev/null)
CPU_INFO=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | xargs)
CPU_CORES=$(nproc 2>/dev/null)
TOTAL_MEM=$(free -h | awk '/^Mem:/ {print $2}')
TOTAL_DISK=$(df -h / | awk 'NR==2 {print $2}')
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "unavailable")
LOAD_AVERAGE=$(uptime | awk -F'load average:' '{print $2}' | xargs)

print_info "Hostname" "$(hostname)"
print_info "Operating System" "$OS_INFO"
print_info "Kernel Version" "$KERNEL_VERSION"
print_info "Uptime" "$UPTIME (since $UPTIME_SINCE)"
print_info "CPU Model" "$CPU_INFO"
print_info "CPU Cores" "$CPU_CORES"
print_info "Total Memory" "$TOTAL_MEM"
print_info "Total Disk Space" "$TOTAL_DISK"
print_info "Public IP" "$PUBLIC_IP"
print_info "Load Average" "$LOAD_AVERAGE"
echo "" >>"$REPORT_FILE"

# ---------------------------------------------------------------------------
# Security Audit
# ---------------------------------------------------------------------------
print_header "Security Audit Results"

# System restart required
if [ -f /var/run/reboot-required ]; then
    check_security "System Restart" "WARN" "System requires a restart to apply updates"
else
    check_security "System Restart" "PASS" "No restart required"
fi

# --------------------------------------------------------------------------
# #7 SSH: read the daemon's EFFECTIVE configuration via `sshd -T`.
#     Falls back to grep only if sshd -T is unavailable (no root / no sshd).
# --------------------------------------------------------------------------
SSHD_EFFECTIVE=""
if command -v sshd >/dev/null 2>&1; then
    SSHD_EFFECTIVE=$(sshd -T 2>/dev/null)
fi

sshd_get() {
    # $1 = lowercase directive; prints first value, empty if absent
    local key="$1"
    if [ -n "$SSHD_EFFECTIVE" ]; then
        echo "$SSHD_EFFECTIVE" | awk -v k="$key" 'tolower($1)==k {print $2; exit}'
    else
        # Best-effort fallback: main config only (drop-ins not resolved here)
        grep -iE "^[[:space:]]*${key}[[:space:]]" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}'
    fi
}

if [ -z "$SSHD_EFFECTIVE" ] && [ ! -r /etc/ssh/sshd_config ]; then
    check_security "SSH Configuration" "WARN" "Could not read effective SSH config (run as root; is openssh-server installed?)"
else
    # PermitRootLogin
    SSH_ROOT=$(sshd_get "permitrootlogin")
    SSH_ROOT=${SSH_ROOT:-prohibit-password}
    case "$SSH_ROOT" in
        no)
            check_security "SSH Root Login" "PASS" "Root login is disabled (PermitRootLogin no)"
            ;;
        prohibit-password | forced-commands-only | without-password)
            check_security "SSH Root Login" "WARN" "Root login restricted to keys only ($SSH_ROOT) - set 'PermitRootLogin no' for full lockout"
            ;;
        *)
            check_security "SSH Root Login" "FAIL" "Root login is allowed ($SSH_ROOT) - set 'PermitRootLogin no' in /etc/ssh/sshd_config"
            ;;
    esac

    # PasswordAuthentication
    SSH_PASSWORD=$(sshd_get "passwordauthentication")
    SSH_PASSWORD=${SSH_PASSWORD:-yes}
    if [ "$SSH_PASSWORD" = "no" ]; then
        check_security "SSH Password Auth" "PASS" "Password authentication is disabled, key-based auth only"
    else
        check_security "SSH Password Auth" "FAIL" "Password authentication is enabled - use key-based authentication only"
    fi

    # Port
    UNPRIV_START=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)
    SSH_PORT=$(sshd_get "port")
    SSH_PORT=${SSH_PORT:-22}
    if [ "$SSH_PORT" = "22" ]; then
        check_security "SSH Port" "WARN" "Using default port 22 - a non-standard port reduces automated scanning noise"
    elif [ "$SSH_PORT" -ge "$UNPRIV_START" ] 2>/dev/null; then
        check_security "SSH Port" "FAIL" "Using unprivileged port $SSH_PORT - use a port below $UNPRIV_START so non-root users cannot bind it"
    else
        check_security "SSH Port" "PASS" "Using non-default privileged port $SSH_PORT"
    fi
fi

# --------------------------------------------------------------------------
# #2 Firewall: verify it actually filters, not merely that a tool exists.
# --------------------------------------------------------------------------
check_firewall_status() {
    if command -v ufw >/dev/null 2>&1; then
        if ufw status 2>/dev/null | grep -qw "active"; then
            check_security "Firewall Status (UFW)" "PASS" "UFW is active and enforcing rules"
        else
            check_security "Firewall Status (UFW)" "FAIL" "UFW is installed but inactive - run 'ufw enable'"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            check_security "Firewall Status (firewalld)" "PASS" "firewalld is running"
        else
            check_security "Firewall Status (firewalld)" "FAIL" "firewalld is installed but not running"
        fi
    elif command -v nft >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
        if nft list ruleset 2>/dev/null | grep -qE 'hook[[:space:]]+input' \
            && nft list ruleset 2>/dev/null | grep -qE 'policy[[:space:]]+drop|(drop|reject)$'; then
            check_security "Firewall Status (nftables)" "PASS" "nftables has an input chain with a drop/reject policy"
        else
            check_security "Firewall Status (nftables)" "WARN" "nftables ruleset present but no restrictive input policy detected"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        IPT=$(iptables -S INPUT 2>/dev/null)
        IPT_POLICY=$(echo "$IPT" | awk '/^-P INPUT/ {print $3}')
        IPT_RULES=$(echo "$IPT" | grep -vcE '^(-P|-N)')
        if [ "$IPT_POLICY" = "DROP" ] || [ "$IPT_POLICY" = "REJECT" ]; then
            check_security "Firewall Status (iptables)" "PASS" "INPUT chain default policy is $IPT_POLICY"
        elif [ "${IPT_RULES:-0}" -gt 0 ]; then
            check_security "Firewall Status (iptables)" "WARN" "INPUT policy is ACCEPT but $IPT_RULES rules exist - verify they actually restrict traffic"
        else
            check_security "Firewall Status (iptables)" "FAIL" "INPUT policy is ACCEPT with no rules - the host is not firewalled"
        fi
    else
        check_security "Firewall Status" "FAIL" "No recognised firewall tool (ufw/firewalld/nft/iptables) is installed"
    fi
}
check_firewall_status

# Unattended upgrades (Debian/Ubuntu)
if command -v dpkg >/dev/null 2>&1 && dpkg -l 2>/dev/null | grep -q "unattended-upgrades"; then
    check_security "Unattended Upgrades" "PASS" "Automatic security updates are configured"
elif command -v dpkg >/dev/null 2>&1; then
    check_security "Unattended Upgrades" "FAIL" "unattended-upgrades not installed - system may miss critical security updates"
else
    check_security "Unattended Upgrades" "WARN" "Non-Debian system - verify automatic updates via your distro's mechanism"
fi

# Intrusion prevention (Fail2ban / CrowdSec, host or container)
IPS_INSTALLED=0
IPS_ACTIVE=0
if command -v dpkg >/dev/null 2>&1; then
    if dpkg -l 2>/dev/null | grep -q "fail2ban"; then
        IPS_INSTALLED=1
        systemctl is-active --quiet fail2ban && IPS_ACTIVE=1
    fi
    if dpkg -l 2>/dev/null | grep -q "crowdsec"; then
        IPS_INSTALLED=1
        systemctl is-active --quiet crowdsec && IPS_ACTIVE=1
    fi
fi
if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
    if docker ps -a --format '{{.Image}} {{.Names}}' 2>/dev/null | grep -qiE 'fail2ban|crowdsec'; then
        IPS_INSTALLED=1
        docker ps --format '{{.Image}} {{.Names}}' 2>/dev/null | grep -qiE 'fail2ban|crowdsec' && IPS_ACTIVE=1
    fi
fi
case "$IPS_INSTALLED$IPS_ACTIVE" in
    "11") check_security "Intrusion Prevention" "PASS" "Fail2ban or CrowdSec is installed and running" ;;
    "10") check_security "Intrusion Prevention" "WARN" "Fail2ban or CrowdSec is installed but not running" ;;
    *) check_security "Intrusion Prevention" "FAIL" "No intrusion prevention system (Fail2ban or CrowdSec) is installed" ;;
esac

# --------------------------------------------------------------------------
# #1 Failed logins: execute the log source correctly; include rotation.
# --------------------------------------------------------------------------
FAILED_LOGINS=0
LOGIN_SRC="unknown"
if [ -r /var/log/auth.log ]; then
    # grep -h across rotated files then count lines (grep -c would emit per-file counts)
    # shellcheck disable=SC2126
    FAILED_LOGINS=$(grep -h "Failed password" /var/log/auth.log /var/log/auth.log.1 2>/dev/null | wc -l)
    LOGIN_SRC="/var/log/auth.log"
elif [ -r /var/log/secure ]; then
    # shellcheck disable=SC2126
    FAILED_LOGINS=$(grep -h "Failed password" /var/log/secure /var/log/secure.1 2>/dev/null | wc -l)
    LOGIN_SRC="/var/log/secure"
elif command -v journalctl >/dev/null 2>&1; then
    FAILED_LOGINS=$(journalctl _COMM=sshd --since "24 hours ago" 2>/dev/null | grep -c "Failed password")
    LOGIN_SRC="journalctl (last 24h)"
else
    check_security "Auth Log" "WARN" "No readable auth log or journal - cannot assess failed logins (run as root?)"
fi
FAILED_LOGINS=$(printf '%s' "$FAILED_LOGINS" | tr -cd '0-9')
FAILED_LOGINS=${FAILED_LOGINS:-0}
FAILED_LOGINS=$((10#$FAILED_LOGINS))

if [ "$FAILED_LOGINS" -lt 10 ]; then
    check_security "Failed Logins" "PASS" "$FAILED_LOGINS failed login attempts ($LOGIN_SRC) - within normal range"
elif [ "$FAILED_LOGINS" -lt 50 ]; then
    check_security "Failed Logins" "WARN" "$FAILED_LOGINS failed login attempts ($LOGIN_SRC) - possible probing"
else
    check_security "Failed Logins" "FAIL" "$FAILED_LOGINS failed login attempts ($LOGIN_SRC) - possible brute-force attack"
fi

# System updates (Debian/Ubuntu) - distinguish security from non-security
if command -v apt-get >/dev/null 2>&1; then
    APT_SIM=$(apt-get -s upgrade 2>/dev/null)
    ALL_UPDATES=$(echo "$APT_SIM" | grep -cE '^Inst ')
    # Security updates come from a suite/archive containing "-security"
    SEC_UPDATES=$(echo "$APT_SIM" | grep -E '^Inst ' | grep -ciE '\-security|Debian-Security')
    if [ "$SEC_UPDATES" -gt 0 ]; then
        check_security "System Updates" "FAIL" "$SEC_UPDATES security update(s) pending (of $ALL_UPDATES total) - apply immediately (run 'apt update' first for accuracy)"
    elif [ "$ALL_UPDATES" -gt 0 ]; then
        check_security "System Updates" "WARN" "$ALL_UPDATES non-security package update(s) available - schedule maintenance"
    else
        check_security "System Updates" "PASS" "All apt packages are up to date (run 'apt update' first for accuracy)"
    fi
else
    check_security "System Updates" "WARN" "apt not present - check updates via your distro's package manager"
fi

# Running services
if command -v systemctl >/dev/null 2>&1; then
    SERVICES=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c "loaded active running")
    if [ "$SERVICES" -lt 35 ]; then
        check_security "Running Services" "PASS" "$SERVICES services running - reasonable for a typical server"
    elif [ "$SERVICES" -lt 60 ]; then
        check_security "Running Services" "WARN" "$SERVICES services running - review whether all are needed"
    else
        check_security "Running Services" "FAIL" "Too many services running ($SERVICES) - increases attack surface"
    fi
fi

# --------------------------------------------------------------------------
# #4 Ports: parse the bind address to separate public from loopback.
# --------------------------------------------------------------------------
if command -v ss >/dev/null 2>&1; then
    LISTEN_RAW=$(ss -tuln 2>/dev/null | awk 'NR>1 {print $5}')
elif command -v netstat >/dev/null 2>&1; then
    LISTEN_RAW=$(netstat -tuln 2>/dev/null | awk '/LISTEN|udp/ {print $4}')
else
    LISTEN_RAW=""
    check_security "Port Security" "WARN" "Neither 'ss' nor 'netstat' available - cannot enumerate listening ports"
fi

if [ -n "$LISTEN_RAW" ]; then
    ALL_PORTS=()
    PUBLIC_PORTS=()
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        port=${entry##*:}
        addr=${entry%:*}
        addr=${addr#[}
        addr=${addr%]} # strip IPv6 brackets
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        ALL_PORTS+=("$port")
        case "$addr" in
            127.0.0.1 | ::1 | localhost) ;; # loopback = not exposed
            *) PUBLIC_PORTS+=("$port") ;;
        esac
    done <<<"$LISTEN_RAW"

    TOTAL_UNIQ=$(printf '%s\n' "${ALL_PORTS[@]}" | sort -un | tr '\n' ',' | sed 's/,$//')
    PUB_UNIQ=$(printf '%s\n' "${PUBLIC_PORTS[@]}" | sort -un | tr '\n' ',' | sed 's/,$//')
    TOTAL_N=$(printf '%s\n' "${ALL_PORTS[@]}" | sort -un | grep -c .)
    PUB_N=$(printf '%s\n' "${PUBLIC_PORTS[@]}" | sort -un | grep -c .)

    if [ "$PUB_N" -lt 3 ]; then
        check_security "Port Security" "PASS" "$PUB_N internet-facing ports [$PUB_UNIQ] (total listening: $TOTAL_N [$TOTAL_UNIQ])"
    elif [ "$PUB_N" -lt 5 ]; then
        check_security "Port Security" "WARN" "$PUB_N internet-facing ports [$PUB_UNIQ] - review exposure (total: $TOTAL_N)"
    else
        check_security "Port Security" "FAIL" "$PUB_N internet-facing ports [$PUB_UNIQ] - high exposure, firewall unneeded ones (total: $TOTAL_N)"
    fi
fi

# Disk usage
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
DISK_USAGE=$(df -h / | awk 'NR==2 {print int($5)}')
if [ "$DISK_USAGE" -lt 50 ]; then
    check_security "Disk Usage" "PASS" "Healthy disk space (${DISK_USAGE}% used - ${DISK_USED} of ${DISK_TOTAL}, ${DISK_AVAIL} free)"
elif [ "$DISK_USAGE" -lt 80 ]; then
    check_security "Disk Usage" "WARN" "Moderate disk usage (${DISK_USAGE}% used - ${DISK_USED} of ${DISK_TOTAL}, ${DISK_AVAIL} free)"
else
    check_security "Disk Usage" "FAIL" "Critical disk usage (${DISK_USAGE}% used - ${DISK_USED} of ${DISK_TOTAL}, ${DISK_AVAIL} free)"
fi

# Memory usage
MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
MEM_USAGE=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
if [ "$MEM_USAGE" -lt 50 ]; then
    check_security "Memory Usage" "PASS" "Healthy memory usage (${MEM_USAGE}% used - ${MEM_USED} of ${MEM_TOTAL}, ${MEM_AVAIL} available)"
elif [ "$MEM_USAGE" -lt 80 ]; then
    check_security "Memory Usage" "WARN" "Moderate memory usage (${MEM_USAGE}% used - ${MEM_USED} of ${MEM_TOTAL}, ${MEM_AVAIL} available)"
else
    check_security "Memory Usage" "FAIL" "Critical memory usage (${MEM_USAGE}% used - ${MEM_USED} of ${MEM_TOTAL}, ${MEM_AVAIL} available)"
fi

# CPU usage - sample /proc/stat over 1s (accurate, locale-independent).
# top -bn1 reports the since-boot average on its first sample, not current load.
CPU_CORES=$(nproc)
CPU_LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')
if [ -r /proc/stat ]; then
    read -r _ u1 n1 s1 i1 w1 x1 y1 z1 _ </proc/stat
    sleep 1
    read -r _ u2 n2 s2 i2 w2 x2 y2 z2 _ </proc/stat
    IDLE1=$((i1 + w1))
    IDLE2=$((i2 + w2))
    TOT1=$((u1 + n1 + s1 + i1 + w1 + x1 + y1 + z1))
    TOT2=$((u2 + n2 + s2 + i2 + w2 + x2 + y2 + z2))
    DTOT=$((TOT2 - TOT1))
    DIDLE=$((IDLE2 - IDLE1))
    if [ "$DTOT" -gt 0 ]; then
        CPU_USAGE=$((100 * (DTOT - DIDLE) / DTOT))
        CPU_IDLE=$((100 * DIDLE / DTOT))
    else
        CPU_USAGE=0
        CPU_IDLE=100
    fi
else
    CPU_USAGE=$(top -bn1 | awk '/Cpu\(s\)/{print int($2); exit}')
    CPU_IDLE=$((100 - CPU_USAGE))
fi
if [ "$CPU_USAGE" -lt 50 ]; then
    check_security "CPU Usage" "PASS" "Healthy CPU usage (${CPU_USAGE}% - Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
elif [ "$CPU_USAGE" -lt 80 ]; then
    check_security "CPU Usage" "WARN" "Moderate CPU usage (${CPU_USAGE}% - Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
else
    check_security "CPU Usage" "FAIL" "Critical CPU usage (${CPU_USAGE}% - Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
fi

# --------------------------------------------------------------------------
# #5 Sudo logging: syslog is the secure DEFAULT; only FAIL if disabled.
# --------------------------------------------------------------------------
if [ -r /etc/sudoers ]; then
    if grep -rqE '^[[:space:]]*Defaults[[:space:]!,=]*!syslog' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        check_security "Sudo Logging" "FAIL" "Sudo syslog logging is explicitly disabled (!syslog) - re-enable audit logging"
    elif grep -rqE '^[[:space:]]*Defaults.*(logfile|syslog)' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        check_security "Sudo Logging" "PASS" "Sudo logging is explicitly configured (logfile/syslog)"
    else
        check_security "Sudo Logging" "PASS" "Sudo logs to syslog by default (auth.log) - logging is in effect"
    fi
else
    check_security "Sudo Logging" "WARN" "Cannot read /etc/sudoers (run as root) - unable to verify sudo logging"
fi

# --------------------------------------------------------------------------
# #6 Password policy: comment-aware, >=12, checks .d overrides and PAM.
# --------------------------------------------------------------------------
PWQ_MINLEN=$(grep -rhE '^[[:space:]]*minlen[[:space:]]*=' \
    /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null \
    | tail -1 | grep -oE '[0-9]+' | head -1)

if [ -n "$PWQ_MINLEN" ]; then
    if [ "$PWQ_MINLEN" -ge 12 ]; then
        check_security "Password Policy" "PASS" "Strong password policy enforced (pwquality minlen=$PWQ_MINLEN)"
    else
        check_security "Password Policy" "FAIL" "Weak password policy (pwquality minlen=$PWQ_MINLEN) - set minlen >= 12"
    fi
elif grep -rqE 'pam_(pwquality|cracklib)\.so' /etc/pam.d/ 2>/dev/null; then
    check_security "Password Policy" "WARN" "A PAM password-quality module is active but no explicit minlen>=12 was found - verify strength rules"
else
    check_security "Password Policy" "FAIL" "No password quality policy configured - system accepts weak passwords"
fi

# --------------------------------------------------------------------------
# #3 SUID files: bounded scan (-xdev), verified against the package DB.
#     A SUID binary NOT owned by any package is what actually matters.
# --------------------------------------------------------------------------
SUID_LIST=$(find / -xdev -type f -perm -4000 \
    ! -path '/proc/*' ! -path '/sys/*' ! -path '/run/*' 2>/dev/null)
SUID_TOTAL=$(printf '%s\n' "$SUID_LIST" | grep -c .)

if command -v dpkg >/dev/null 2>&1; then
    PKG_VERIFY="dpkg -S"
elif command -v rpm >/dev/null 2>&1; then PKG_VERIFY="rpm -qf"; else PKG_VERIFY=""; fi

if [ -z "$SUID_LIST" ]; then
    check_security "SUID Files" "PASS" "No SUID-root files found"
elif [ -n "$PKG_VERIFY" ]; then
    UNOWNED=0
    UNOWNED_LIST=""
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        if ! $PKG_VERIFY "$f" >/dev/null 2>&1; then
            UNOWNED=$((UNOWNED + 1))
            UNOWNED_LIST="$UNOWNED_LIST $f"
        fi
    done <<<"$SUID_LIST"
    if [ "$UNOWNED" -eq 0 ]; then
        check_security "SUID Files" "PASS" "$SUID_TOTAL SUID files, all owned by installed packages"
    else
        check_security "SUID Files" "FAIL" "$UNOWNED of $SUID_TOTAL SUID-root files are NOT owned by any package - investigate:${UNOWNED_LIST}"
    fi
else
    check_security "SUID Files" "WARN" "$SUID_TOTAL SUID-root files found; no package manager to verify them - review manually: $(printf '%s' "$SUID_LIST" | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
# Summary (#8)
# ---------------------------------------------------------------------------
{
    echo "================================"
    echo "Summary: PASS=$PASS_COUNT WARN=$WARN_COUNT FAIL=$FAIL_COUNT"
    echo "System: $(hostname) | $(uname -r) | $OS_INFO"
    echo "================================"
    echo "End of VPS Audit Report"
} >>"$REPORT_FILE"
chmod 600 "$REPORT_FILE" 2>/dev/null || true

EXIT_CODE=0
[ "$FAIL_COUNT" -gt 0 ] && EXIT_CODE=1
if $STRICT && [ "$WARN_COUNT" -gt 0 ]; then EXIT_CODE=1; fi

if $JSON_OUTPUT; then
    printf '{\n'
    printf '  "timestamp": "%s",\n' "$TIMESTAMP"
    printf '  "hostname": "%s",\n' "$(json_escape "$(hostname)")"
    printf '  "summary": { "pass": %d, "warn": %d, "fail": %d },\n' "$PASS_COUNT" "$WARN_COUNT" "$FAIL_COUNT"
    printf '  "exit_code": %d,\n' "$EXIT_CODE"
    printf '  "results": [\n'
    n=${#JSON_ITEMS[@]}
    for i in "${!JSON_ITEMS[@]}"; do
        sep=","
        [ "$i" -eq "$((n - 1))" ] && sep=""
        printf '    %s%s\n' "${JSON_ITEMS[$i]}" "$sep"
    done
    printf '  ]\n}\n'
else
    say "\n${BOLD}Summary:${NC} ${GREEN}PASS=$PASS_COUNT${NC} ${YELLOW}WARN=$WARN_COUNT${NC} ${RED}FAIL=$FAIL_COUNT${NC}"
    say "VPS audit complete. Full report saved to $REPORT_FILE"
fi

exit "$EXIT_CODE"
