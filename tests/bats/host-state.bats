#!/usr/bin/env bats
#
# Mocked host-state tests. The script is sourced (its guarded main() does not
# run), exposing the pure eval_* decision functions. Each test feeds a mocked
# host state and asserts the resulting status — no real host access, fully
# deterministic.

setup() {
    # Sourcing must not execute the audit.
    source "${BATS_TEST_DIRNAME}/../../scripts/vps-audit.sh"
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
