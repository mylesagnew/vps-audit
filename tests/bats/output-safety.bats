#!/usr/bin/env bats
#
# Report-file safety (HIGH finding #1). These --output rejections happen in
# safe_open_report(), before any host checks, so they are fast and hermetic.

setup() {
    SCRIPT="${BATS_TEST_DIRNAME}/../../scripts/vps-audit.sh"
    TMP="$(mktemp -d)"
}

teardown() {
    rm -rf "$TMP"
}

@test "refuses to write through a symlink and leaves the target intact" {
    printf 'SECRET\n' >"$TMP/victim"
    ln -s "$TMP/victim" "$TMP/link"
    run bash "$SCRIPT" --no-public-ip -o "$TMP/link"
    [ "$status" -eq 2 ]
    [[ "$output" == *"symlink"* ]]
    [ "$(cat "$TMP/victim")" = "SECRET" ]
}

@test "refuses to overwrite an existing file" {
    printf 'EXISTING\n' >"$TMP/exists"
    run bash "$SCRIPT" --no-public-ip -o "$TMP/exists"
    [ "$status" -eq 2 ]
    [[ "$output" == *"overwrite"* ]]
    [ "$(cat "$TMP/exists")" = "EXISTING" ]
}

@test "refuses when the parent directory does not exist" {
    run bash "$SCRIPT" --no-public-ip -o "$TMP/missing/report.txt"
    [ "$status" -eq 2 ]
    [[ "$output" == *"parent directory"* ]]
}

@test "refuses a world-writable parent without the sticky bit" {
    mkdir "$TMP/ww"
    chmod 0777 "$TMP/ww"
    run bash "$SCRIPT" --no-public-ip -o "$TMP/ww/report.txt"
    [ "$status" -eq 2 ]
    [[ "$output" == *"world-writable"* ]]
    [ ! -e "$TMP/ww/report.txt" ]
}

@test "allows a world-writable parent WITH the sticky bit (e.g. /tmp-like)" {
    mkdir "$TMP/sticky"
    chmod 1777 "$TMP/sticky"
    run bash "$SCRIPT" --no-public-ip -o "$TMP/sticky/report.txt"
    [ "$status" -le 1 ]
    [ -f "$TMP/sticky/report.txt" ]
    [ "$(stat -c '%a' "$TMP/sticky/report.txt")" = "600" ]
}

@test "refuses a non-regular target (e.g. a directory)" {
    mkdir "$TMP/adir"
    run bash "$SCRIPT" --no-public-ip -o "$TMP/adir"
    [ "$status" -eq 2 ]
    [[ "$output" == *"non-regular"* ]]
}

@test "creates a fresh report with 0600 permissions" {
    run bash "$SCRIPT" --no-public-ip -o "$TMP/report.txt"
    # exit code reflects findings (0/1), never a crash (>1)
    [ "$status" -le 1 ]
    [ -f "$TMP/report.txt" ]
    [ "$(stat -c '%a' "$TMP/report.txt")" = "600" ]
}
