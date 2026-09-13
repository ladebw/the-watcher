"""A small worker process, protected by ``examples/protect_agent.py``.

It only does ordinary work: no policy violations, no tripwires. The point is
to show the session lifecycle and a clean trace.
"""

from __future__ import annotations

import sys
import time


def main() -> int:
    print("[worker] starting")
    for step in range(3):
        time.sleep(0.2)
        print(f"[worker] step {step + 1}/3")
    print("[worker] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
