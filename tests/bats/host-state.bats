#!/usr/bin/env bats
#
# Mocked host-state tests. The script is sourced (its guarded main() does not
# run), exposing the pure eval_* decision functions. Each test feeds a mocked
# host state and asserts the resulting status — no real host access, fully
# deterministic.

setup() {
    SCRIPT="${BATS_TEST_DIRNAME}/../../scripts/vps-audit.sh"
    # Sourcing must not execute the audit.
    source "$SCRIPT"
}

status_of() { printf '%s' "${1%%|*}"; }

# --- threshold primitive -------------------------------------------------

@test "status_from_thresholds maps below/between/above bands" {
    [ "$(status_from_thresholds 0 10 50)" = PASS ]
    [ "$(status_from_thresholds 9 10 50)" = PASS ]
    [ "$(status_from_thresholds 10 10 50)" = WARN ]
    [ "$(status_from_thresholds 49 10 50)" = WARN ]
    [ "$(status_from_thresholds 50 10 50)" = FAIL ]
    [ "$(status_from_thresholds 999 10 50)" = FAIL ]
}

# --- SSH root login ------------------------------------------------------

@test "ssh root login: 'no' passes, key-only warns, 'yes' fails" {
    [ "$(status_of "$(eval_ssh_root_login no)")" = PASS ]
    [ "$(status_of "$(eval_ssh_root_login prohibit-password)")" = WARN ]
    [ "$(status_of "$(eval_ssh_root_login forced-commands-only)")" = WARN ]
    [ "$(status_of "$(eval_ssh_root_login yes)")" = FAIL ]
}

# --- SSH password auth ---------------------------------------------------

@test "ssh password auth: 'no' passes, anything else fails" {
    [ "$(status_of "$(eval_ssh_password no)")" = PASS ]
    [ "$(status_of "$(eval_ssh_password yes)")" = FAIL ]
}

# --- SSH port ------------------------------------------------------------

@test "ssh port: 22 warns, unprivileged fails, privileged non-default passes" {
    [ "$(status_of "$(eval_ssh_port 22 1024)")" = WARN ]
    [ "$(status_of "$(eval_ssh_port 2222 1024)")" = FAIL ]
    [ "$(status_of "$(eval_ssh_port 443 1024)")" = PASS ]
}

# --- firewall (iptables policy) ------------------------------------------

@test "iptables firewall: DROP/REJECT pass, ACCEPT+rules warns, ACCEPT+none fails" {
    [ "$(status_of "$(eval_firewall_iptables DROP 0)")" = PASS ]
    [ "$(status_of "$(eval_firewall_iptables REJECT 0)")" = PASS ]
    [ "$(status_of "$(eval_firewall_iptables ACCEPT 5)")" = WARN ]
    [ "$(status_of "$(eval_firewall_iptables ACCEPT 0)")" = FAIL ]
}

# --- intrusion prevention ------------------------------------------------

@test "ips: installed+active pass, installed-only warns, absent fails" {
    [ "$(status_of "$(eval_ips 1 1)")" = PASS ]
    [ "$(status_of "$(eval_ips 1 0)")" = WARN ]
    [ "$(status_of "$(eval_ips 0 0)")" = FAIL ]
}

# --- system updates ------------------------------------------------------

@test "updates: security fails, non-security warns, none passes" {
    [ "$(status_of "$(eval_updates 2 5)")" = FAIL ]
    [ "$(status_of "$(eval_updates 0 5)")" = WARN ]
    [ "$(status_of "$(eval_updates 0 0)")" = PASS ]
}

# --- check metadata (severity + remediation) ----------------------------

@test "meta_for returns a valid severity and non-empty remediation for known ids" {
    local id meta sev rem
    for id in ssh-root-login firewall failed-logins system-updates port-security \
        suid-files password-policy sudo-logging disk-usage; do
        meta="$(meta_for "$id")"
        sev="${meta%%|*}"
        rem="${meta#*|}"
        case "$sev" in
            critical | high | medium | low | info) ;;
            *) printf 'bad severity for %s: %s\n' "$id" "$sev" >&2; return 1 ;;
        esac
        [ -n "$rem" ] || { printf 'empty remediation for %s\n' "$id" >&2; return 1; }
    done
}

@test "meta_for falls back to info/empty for unknown ids" {
    [ "$(meta_for definitely-not-a-real-id)" = "info|" ]
}

# --- policy parser -------------------------------------------------------

@test "load_policy overrides known threshold keys" {
    DISK_WARN=50 DISK_FAIL=80
    local f
    f="$(mktemp)"
    printf '# role: db\nDISK_WARN = 60\nDISK_FAIL=85\n\n' >"$f"
    load_policy "$f"
    rm -f "$f"
    [ "$DISK_WARN" = 60 ]
    [ "$DISK_FAIL" = 85 ]
}

@test "load_policy rejects unknown keys and non-integer values" {
    local f
    f="$(mktemp)"
    printf 'BOGUS=1\n' >"$f"
    run bash -c 'source "'"$SCRIPT"'"; load_policy "'"$f"'"'
    [ "$status" -eq 2 ]
    printf 'CPU_WARN=notanumber\n' >"$f"
    run bash -c 'source "'"$SCRIPT"'"; load_policy "'"$f"'"'
    [ "$status" -eq 2 ]
    rm -f "$f"
}
