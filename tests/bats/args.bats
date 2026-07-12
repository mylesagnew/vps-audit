#!/usr/bin/env bats
#
# Argument parsing — these paths exit before any host checks run,
# so they are fast and hermetic.

setup() {
    SCRIPT="${BATS_TEST_DIRNAME}/../../scripts/vps-audit.sh"
    TMP="$(mktemp -d)"
    cd "$TMP"
}

teardown() {
    rm -rf "$TMP"
}

@test "--help exits 0 and prints usage" {
    run bash "$SCRIPT" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
    [[ "$output" == *"--json"* ]]
    [[ "$output" == *"--public-ip"* ]]
    [[ "$output" == *"--no-public-ip"* ]]
}

@test "--help does not run host checks (no report written)" {
    run bash "$SCRIPT" --help
    [ "$status" -eq 0 ]
    run bash -c 'ls vps-audit-report-* 2>/dev/null | wc -l'
    [ "$output" -eq 0 ]
}

@test "unknown flag exits 2" {
    run bash "$SCRIPT" --definitely-not-a-flag
    [ "$status" -eq 2 ]
    [[ "$output" == *"unknown option"* ]]
}

@test "--output with no argument exits 2" {
    run bash "$SCRIPT" --output
    [ "$status" -eq 2 ]
    [[ "$output" == *"needs an argument"* ]]
}
