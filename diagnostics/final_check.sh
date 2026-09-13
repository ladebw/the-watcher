#!/usr/bin/env bash
# End-to-end verification of the V3 containment path on Linux.
#
# Run:  bash diagnostics/final_check.sh
#
# Checks, in order:
#   1. the test suite
#   2. `watcher doctor` on this host
#   3. an enforced session against the network bypass agent
#   4. enforced mode refusing a workspace it cannot contain
#   5. V2 (unenforced) supervision still working
#
# Needs a Linux-native workspace, because Landlock path rules are not honoured
# on 9p/drvfs filesystems and the backend refuses them. The script therefore
# stages its workspace under the system temporary directory.

set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"

# Same interpreter detection as run_tests_linux.sh: use a python that can
# import pytest, creating a cached virtual environment if none can.
python="${PYTHON:-}"
if [ -z "$python" ]; then
    if python3 -c "import pytest" >/dev/null 2>&1; then
        python=python3
    else
        venv="${XDG_CACHE_HOME:-$HOME/.cache}/the-watcher-venv"
        if [ ! -x "$venv/bin/python" ]; then
            echo "creating virtual environment in $venv" >&2
            python3 -m venv "$venv" >/dev/null 2>&1 || exit 1
            "$venv/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1
            "$venv/bin/python" -m pip install --quiet pytest >/dev/null 2>&1 || exit 1
        fi
        python="$venv/bin/python"
    fi
fi

workspace="$(mktemp -d -t watcher-final-ws-XXXXXX)"
storage="$(mktemp -d -t watcher-final-store-XXXXXX)"
trap 'rm -rf "$workspace" "$storage"' EXIT

cd "$repo" || exit 1

echo "############ 1. test suite ############"
"$python" -m pytest --tb=line 2>&1 | tail -5

echo
echo "############ 2. watcher doctor ############"
"$python" -m the_watcher.cli doctor --workspace "$workspace" 2>&1 | tail -14

echo
echo "############ 3. enforced run: network attempts ############"
cp examples/v3_bypass_agents/bypass_agent.py "$workspace/"
"$python" -m the_watcher.cli run --enforced --quiet \
    --workspace "$workspace" --storage-root "$storage" \
    -- "$python" "$workspace/bypass_agent.py" --attempt network \
    --json-out "$workspace/report.json"
echo "exit=$?"

"$python" - "$workspace/report.json" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
print("  contained:", data["contained"], " escaped:", data["escaped"] or "none")
for key in sorted(data):
    entry = data[key]
    if isinstance(entry, dict) and key not in ("status", "identity"):
        mark = "ESCAPED" if entry.get("escaped") else "DENIED "
        print(f"    {mark} {key:<24} {entry.get('detail')}")
PY

echo
echo "############ 4. enforced mode refuses an uncontainable workspace ############"
"$python" -m the_watcher.cli run --enforced --quiet \
    --workspace "$repo" --storage-root "$storage" \
    -- "$python" -c "print('should not run')" 2>&1 | tail -2
echo "exit=${PIPESTATUS[0]}"

echo
echo "############ 5. V2 (unenforced) supervision ############"
"$python" -m the_watcher.cli run --quiet \
    --workspace "$workspace" --storage-root "$storage" \
    -- "$python" -c "print('v2 fine')"
echo "exit=$?"
