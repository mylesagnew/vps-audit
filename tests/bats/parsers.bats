#!/usr/bin/env bats
#
# Isolated unit tests for the extracted, pure host-data parsers and the
# exit-code / output logic. The script is sourced (main() does not run).

setup() {
    source "${BATS_TEST_DIRNAME}/../../scripts/vps-audit.sh"
}

# --- port parser ---------------------------------------------------------

@test "ports_summary separates public from loopback across address forms" {
    run bash -c '
        source "'"${BATS_TEST_DIRNAME}"'/../../scripts/vps-audit.sh"
        printf "%s\n" "0.0.0.0:22" "127.0.0.1:5432" "[::]:80" "[::1]:53" "*:443" "0.0.0.0:22" \
            | ports_summary'
    # total {22,53,80,443,5432}=5 ; public {22,80,443}=3
    [ "$output" = "5|3|22,53,80,443,5432|22,80,443" ]
}

@test "ports_summary handles an empty/whitespace stream" {
    run bash -c 'source "'"${BATS_TEST_DIRNAME}"'/../../scripts/vps-audit.sh"; printf "\n\n" | ports_summary'
    [ "$output" = "0|0||" ]
}

@test "ports_summary ignores non-numeric ports" {
    run bash -c 'source "'"${BATS_TEST_DIRNAME}"'/../../scripts/vps-audit.sh"; printf "%s\n" "0.0.0.0:ssh" "0.0.0.0:22" | ports_summary'
    [ "$output" = "1|1|22|22" ]
}

@test "classify_listen_addr: loopback vs public (incl IPv6 brackets)" {
    [ "$(classify_listen_addr 127.0.0.1)" = loopback ]
    [ "$(classify_listen_addr '[::1]')" = loopback ]
    [ "$(classify_listen_addr 0.0.0.0)" = public ]
    [ "$(classify_listen_addr '[::]')" = public ]
    [ "$(classify_listen_addr 10.0.0.5)" = public ]
}

# --- SUID ownership classifier ------------------------------------------

@test "count_unowned counts files the verifier rejects" {
    run bash -c '
        source "'"${BATS_TEST_DIRNAME}"'/../../scripts/vps-audit.sh"
        fakever() { case "$1" in */evil|*/x) return 1 ;; *) return 0 ;; esac; }
        printf "%s\n" /usr/bin/sudo /tmp/evil /usr/bin/x | count_unowned fakever'
    [ "$output" = "2| /tmp/evil /usr/bin/x" ]
}

@test "count_unowned reports zero when the verifier owns everything" {
    run bash -c '
        source "'"${BATS_TEST_DIRNAME}"'/../../scripts/vps-audit.sh"
        allown() { return 0; }
        printf "%s\n" /usr/bin/sudo /usr/bin/passwd | count_unowned allown'
    [ "$output" = "0|" ]
}

# --- exit-code logic (strict / ignore / fail-on) -------------------------

@test "compute_exit_code: FAIL gates, WARN only under --strict" {
    STRICT=false FAILON_IDS="" IGNORE_IDS=""
    R_ID=(a b) R_STATUS=(PASS FAIL) R_IGN=(false false)
    [ "$(compute_exit_code)" = 1 ]
    R_STATUS=(PASS WARN)
    [ "$(compute_exit_code)" = 0 ]
    STRICT=true
    [ "$(compute_exit_code)" = 1 ]
}

@test "compute_exit_code: --ignore excludes a check from the gate" {
    STRICT=false FAILON_IDS="" IGNORE_IDS=""
    R_ID=(a b) R_STATUS=(PASS FAIL) R_IGN=(false true)
    [ "$(compute_exit_code)" = 0 ]
}

@test "compute_exit_code: --fail-on gates on a specific id's WARN" {
    STRICT=false IGNORE_IDS="" FAILON_IDS="b"
    R_ID=(a b) R_STATUS=(PASS WARN) R_IGN=(false false)
    [ "$(compute_exit_code)" = 1 ]
}

# --- SARIF level mapping -------------------------------------------------

@test "sarif_level maps statuses to SARIF levels" {
    [ "$(sarif_level FAIL)" = error ]
    [ "$(sarif_level WARN)" = warning ]
    [ "$(sarif_level PASS)" = note ]
    [ "$(sarif_level NA)" = none ]
}
