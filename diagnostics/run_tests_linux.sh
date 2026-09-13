#!/usr/bin/env bash
# Run the test suite where Linux-only V3 enforcement applies (WSL2 or Linux).
#
# Run:  bash diagnostics/run_tests_linux.sh [pytest args...]
#
# V3 containment tests need Linux with user namespaces and seccomp, and their
# workspace must be on a Linux-native filesystem. They skip with a reason
# everywhere else, so this script is only about running more of the suite, not
# about a different result.
#
# Override the interpreter with PYTHON=... to use one that already has pytest.

set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
cd "$repo" || exit 1

python="${PYTHON:-}"
if [ -z "$python" ]; then
    if python3 -c "import pytest" >/dev/null 2>&1; then
        python=python3
    else
        # Keep the environment outside /tmp, which is not durable across
        # separate WSL invocations on some setups.
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

exec "$python" -m pytest "$@"
