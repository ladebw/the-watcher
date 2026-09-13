#!/usr/bin/env bash
# Is a Landlock allow-list honoured for a given path?
#
# Run:  bash diagnostics/check_landlock_reach.sh [path ...]
#
# Defaults to a few paths that differ in filesystem type. Override the
# interpreter with PYTHON=... if `python3` is not the one you want.

set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
python="${PYTHON:-python3}"

if [ "$#" -gt 0 ]; then
    paths=("$@")
else
    paths=("$repo" "$HOME" /tmp)
fi

cd "$repo" || exit 1

"$python" - "${paths[@]}" <<'PY'
import sys

sys.path.insert(0, ".")
from the_watcher.enforcement.linux import landlock_ruleset as ll
from the_watcher.enforcement.procfs import filesystem_type

for path in sys.argv[1:]:
    ok, detail = ll.probe_path_access(path)
    print(f"{path:<50} fs={filesystem_type(path):<10} reach={ok}  {detail}")
PY
