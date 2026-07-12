#!/usr/bin/env bats
#
# JSON stdout contract. Runs the full script (host checks included) on the
# CI runner; --no-public-ip avoids the external network call.

setup() {
    SCRIPT="${BATS_TEST_DIRNAME}/../../scripts/vps-audit.sh"
    TMP="$(mktemp -d)"
    cd "$TMP"
}

teardown() {
    rm -rf "$TMP"
}

@test "--json emits valid JSON with the documented top-level keys" {
    run bash "$SCRIPT" --json --no-public-ip
    [ "$status" -le 1 ]
    python3 - "$output" <<'PY'
import json, re, sys
d = json.loads(sys.argv[1])
for k in ("timestamp", "hostname", "summary", "exit_code", "results"):
    assert k in d, f"missing key: {k}"
assert set(d["summary"]) == {"pass", "warn", "fail"}, d["summary"]
assert isinstance(d["results"], list) and d["results"], "results empty"
for r in d["results"]:
    assert set(r) == {"id", "test", "status", "message"}, r
    assert r["status"] in ("PASS", "WARN", "FAIL"), r
    assert re.fullmatch(r"[a-z0-9-]+", r["id"]), f"bad id: {r['id']!r}"
PY
}

@test "--json check ids are stable and unique" {
    run bash "$SCRIPT" --json --no-public-ip
    [ "$status" -le 1 ]
    python3 - "$output" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
ids = [r["id"] for r in d["results"]]
assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"
# A few stable ids that consumers may key on must be present.
for expected in ("ssh-root-login", "firewall", "failed-logins", "suid-files"):
    assert expected in ids, f"missing stable id: {expected}"
PY
}

@test "--json exit_code field matches process exit status" {
    run bash "$SCRIPT" --json --no-public-ip
    rc="$status"
    ec="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["exit_code"])' "$output")"
    [ "$rc" -eq "$ec" ]
}

@test "text report is not written to stdout in --json mode" {
    run bash "$SCRIPT" --json --no-public-ip
    # First non-empty stdout char should begin the JSON object.
    [[ "$output" == "{"* ]]
}
