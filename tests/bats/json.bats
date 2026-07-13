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
for k in ("tool", "timestamp", "hostname", "summary", "exit_code", "results"):
    assert k in d, f"missing key: {k}"
assert set(d["tool"]) == {"name", "version", "commit"}, d["tool"]
assert set(d["summary"]) == {"pass", "warn", "fail", "not_applicable"}, d["summary"]
assert isinstance(d["results"], list) and d["results"], "results empty"
sev = {"critical", "high", "medium", "low", "info"}
for r in d["results"]:
    assert set(r) == {"id", "test", "status", "severity", "message", "remediation", "cis", "evidence", "ignored"}, r
    assert r["status"] in ("PASS", "WARN", "FAIL", "NA"), r
    assert r["severity"] in sev, r
    assert isinstance(r["ignored"], bool), r
    assert isinstance(r["cis"], list), r
    assert isinstance(r["evidence"], str), r
    assert re.fullmatch(r"[a-z0-9-]+", r["id"]), f"bad id: {r['id']!r}"
PY
}

@test "--markdown emits a report with a results table" {
    run bash "$SCRIPT" --markdown --no-public-ip
    [ "$status" -le 1 ]
    [[ "$output" == *"# VPS Security Audit"* ]]
    [[ "$output" == *"| Status | Severity | Check |"* ]]
}

@test "--html emits a self-contained HTML document" {
    run bash "$SCRIPT" --html --no-public-ip
    [ "$status" -le 1 ]
    [[ "$output" == *"<!doctype html>"* ]]
    [[ "$output" == *"<table>"* ]]
    [[ "$output" != *"http://"* ]] # no external assets
}

@test "--jsonl emits one valid JSON object per line" {
    run bash "$SCRIPT" --jsonl --no-public-ip
    [ "$status" -le 1 ]
    python3 - <<PY
import json
lines = [l for l in """$output""".splitlines() if l.strip()]
assert lines, "no jsonl output"
for l in lines:
    o = json.loads(l)
    assert "hostname" in o and "id" in o and "status" in o, o
PY
}

@test "--sarif emits valid SARIF 2.1.0" {
    run bash "$SCRIPT" --sarif --no-public-ip
    [ "$status" -le 1 ]
    python3 - <<PY
import json
d = json.loads(r'''$output''')
assert d["version"] == "2.1.0", d.get("version")
run = d["runs"][0]
assert run["tool"]["driver"]["name"] == "vps-audit"
assert run["tool"]["driver"]["rules"], "no rules"
for res in run["results"]:
    assert res["level"] in ("error", "warning", "note", "none"), res
    assert "ruleId" in res and "message" in res, res
PY
}

@test "--ignore removes a check from the exit gate" {
    # ssh-config or firewall may FAIL in CI; ignore every id that can fail so the
    # gate is satisfied regardless of host state, proving --ignore is honoured.
    run bash "$SCRIPT" --json --no-public-ip
    [ "$status" -le 1 ]
    ids="$(python3 -c 'import json,sys; print(" ".join("--ignore "+r["id"] for r in json.loads(sys.argv[1])["results"]))' "$output")"
    # shellcheck disable=SC2086
    run bash "$SCRIPT" --json --no-public-ip $ids
    [ "$status" -eq 0 ]
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
