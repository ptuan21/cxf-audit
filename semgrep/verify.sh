#!/usr/bin/env bash
# Smoke test for semgrep/zip-slip-taint.yaml: asserts each fixture produces
# exactly one finding, on the expected line (the // ruleid: line — the
# // ok: lines must NOT be flagged). Not using `semgrep --test` because that
# framework crashes (IndexError in relatively_eq) on this repo's layout —
# see CONTRIBUTING.md.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$DIR/zip-slip-taint.yaml"
FAIL=0

check() {
  local file="$1" expected_line="$2"
  local actual
  actual=$(semgrep --config "$CONFIG" --quiet --json "$file" |
    python3 -c "import json,sys; d=json.load(sys.stdin); print('\n'.join(str(r['start']['line']) for r in d['results']))")
  if [ "$actual" != "$expected_line" ]; then
    echo "FAIL: $file — expected finding on line $expected_line, got: [${actual:-none}]"
    FAIL=1
  else
    echo "OK: $file (line $expected_line)"
  fi
}

check "$DIR/fixtures/vulnerable.rs" 11
check "$DIR/fixtures/vulnerable.kt" 9
check "$DIR/fixtures/vulnerable.swift" 7

exit $FAIL
