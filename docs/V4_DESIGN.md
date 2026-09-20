# The Watcher V4 — Design

| | |
|---|---|
| **Status** | Design for review. **No V4 code has been written.** |
| **Base commit** | `070f64271dacb17633b15ed867968344a5d1d94d` (branch `v4`) |
| **Working tree at time of writing** | clean except this file |
| **Baseline test result** | `521 collected, 460 passed, 61 skipped` on Windows / Python 3.14.3 — exit code 0 |
| **Scope of this document** | Audit of V1/V2/V3, and the proposed design for V4. Nothing here is committed, pushed, tagged or merged. |

This document is deliberately written so that every claim about *existing* behaviour
carries a `file:line` citation, and every claim about *future* behaviour is marked
**PROPOSED**. V4's own success criterion is that it does not advertise enforcement
it does not have, so the same standard applies to this document.

---

## 0.0 Approved V4 design decisions (recorded)

These were approved by the project owner before V4 Phase 0 began. They are binding
on all later phases and are the answers to the open decisions in §16.

| # | Decision | Status |
|---|---|---|
| **D1** | The rich public result object lives under **`the_watcher.api`**. The existing public `Decision` **enum** is not replaced or renamed. | Approved. Resolves ODD-1. |
| **D2** | Policy V1's normative format is **JSON first**. **No YAML in this phase.** YAML may be considered later, only with strict semantics (no silent coercion, unsupported constructs rejected). | Approved. Resolves ODD-3 in favour of the JSON-first option. |
| **D3** | **`network=restricted` remains REFUSED** until it is genuinely enforced. Proxy-only or DNS-only filtering must never be shipped and called OS enforcement. | Approved. Resolves ODD-6 as "keep refusing". |
| **D4** | The **policy-document digest** and the **resolved-policy digest** remain **separate, domain-separated** digests. | Approved. Fixes §4.5. |
| **D5** | Policy digests belong **inside hashed PoE metadata**, not in a new top-level PoE event field. The frozen event schema and `schema_version = "watcher-poe/1"` are unchanged. | Approved. Matches constraint C-1. |
| **D6** | Rate limits will use **deterministic fixed windows over authoritative supervisor state**, as specified in §6. | Approved. |

### 0.0.1 Phase 0 status

V4 Phase 0 — **V3 trust-boundary hardening** — was executed against the defects in
§3.1 and §3.2 before any V4 feature work. It changed no public API, no CLI flag, no
exit code and no PoE event field. The defects it addresses, and how they were
resolved, are recorded in §19.

| Blocker | Subject | Outcome |
|---|---|---|
| **A** | Finalisation must not orphan the workload | **FIXED** |
| **B** | `verify_empty` soundness and containment-unit identity | **FIXED** for the nested-namespace escape, proven on Linux (§19.8). The independent cgroup emptiness proof is **STILL UNSOLVED** (Phase 7) |
| **C** | Authority of the facts a policy decision is built from | **FIXED** for the decision path; cooperative rules are now labelled rather than implied authoritative (**MITIGATED**, not eliminated) |
| **D** | Declared versus enforced containment configuration | **FIXED** by refusal plus recorded waiver; cgroup-backed enforcement remains a later phase |
| **Signals** | `SIGINT`/`SIGTERM` handling | **FIXED** (main-thread only; Windows behaviour unchanged) |
| **PoE** | Truthful lifecycle vocabulary | **FIXED** |
| **Legacy `clone`** | Namespace creation from inside the sandbox | **FIXED** — denied by an argument-aware seccomp rule on the `CLONE_NEW*` mask, with `clone` itself still callable so threads and subprocesses work (§19.8) |

---

## 0. How to read this document

### 0.1 Implemented / not implemented at this commit

Several things named in the V4 brief already exist in some form. Reading the brief
without this table is how a project ends up shipping documentation for features it
does not have.

| Capability | State at `070f642` | Evidence |
|---|---|---|
| Deterministic policy engine (pure, no model) | **Implemented** | `watcher/policy.py:155-465`; verified by `tests/test_policy.py` |
| Tripwires outranking policy, KILL on touch | **Implemented** | `watcher/watcher.py:363-390`, `watcher/tripwire.py:229-339` |
| Hash-chained PoE, canonical JSON, tamper-evident | **Implemented** | `poe/event.py:176-205`, `poe/canonical.py:125-138` |
| Trace verifier with machine-readable signals | **Implemented** | `poe/verifier.py:110-172` |
| External supervisor owning policy/PoE/kill | **Implemented** | `supervisor/daemon.py:1127-1209` |
| Authenticated local IPC, authority-field stripping | **Implemented** | `ipc/server.py:483-541`, `ipc/protocol.py:115-125` |
| Fail-closed client default | **Implemented** (client-side only) | `ipc/client.py:338-354` |
| OS containment: user/pid/mnt/ipc/uts namespaces | **Implemented** (Linux) | `enforcement/backends/namespaces.py:652-667` |
| Landlock allow-list, seccomp denylist, rlimits | **Implemented** (Linux) | `enforcement/linux/*` |
| Empty-network-namespace isolation (`network=none`) | **Implemented** (Linux) | `enforcement/backends/namespaces.py:666-667` |
| **Restricted egress (`network=restricted`)** | **Refused, not implemented** | `enforcement/backends/namespaces.py:168-176`, `backends/docker.py:87-91` |
| **cgroup enforcement (memory/pids/cpu)** | **Not implemented** — probe only | `capabilities.py:312-323`; no write to any cgroup file anywhere |
| **Policy digest** | **Absent** | no `policy_digest` in the tree; contrast `profile_digest` at `enforcement/profile.py:366-373` |
| **Layered policy / precedence** | **Absent** | no `PolicyLayer`/`PolicyResolver` anywhere |
| **Rate limits** | **Absent** | no counter, bucket or limiter in `ipc/` or `supervisor/` |
| **Public Integration API / SDK** | **Absent** | no `WatcherClient` in the public package; `ipc/client.py` is internal and env-driven |
| **Generic adapter contract** | **Absent** | no adapter surface at all |
| **External PoE anchor** | **Absent** | acknowledged as unimplemented at `README.md:232-235` |
| `watcher policy validate/resolve/digest` | **Absent** | only `run, status, verify, demo, doctor` — `cli.py:49,265,273,281,292` |

### 0.2 The one-sentence summary of the audit

V1/V2/V3 built a **sound deterministic decision core and a genuinely kernel-enforced
containment layer**, with two structural gaps: `verify_empty`/policy are not bound to
a versioned identity, and the *facts* fed to the policy engine are unverified client
assertions. V4's job is to add the public contract (policy, API, limits, anchor)
**without touching the core**, and to fix the honesty and lifecycle defects found in
§3 — not to rewrite anything.

---

## 1. Current architecture map

### 1.1 Package layout

```
the_watcher/
  __init__.py           public V1 surface (61 names, __all__ at __init__.py:107-176)
  exceptions.py         the full error vocabulary (exceptions.py:9-34)
  cli.py                watch: run / status / verify / demo / doctor
  watcher/              THE DETERMINISTIC CORE (V1)
    policy.py           pure rule engine, 11 ordered checks
    decision.py         Decision/Risk enums, Evaluation, max_decision
    matching.py         path/domain/tool normalisation and matching
    tripwire.py         canary registry; outranks policy
    kill_switch.py      one-way kill state machine
    signals.py          host-signal vocabulary -> decision
    watcher.py          PoEWatcher, Session: orchestration of the above
  poe/                  PROOF OF EXECUTION
    canonical.py        canonical JSON + sha256 (the determinism substrate)
    event.py            PoEEvent, EventType (45 members)
    trace.py            ExecutionTrace: sequence, chain, seal, relink
    recorder.py         the only locked writer (RLock)
    redact.py           redaction before hashing
    verifier.py         TraceVerifier, TamperSignal, VerificationResult
  ipc/                  V2 TRUST BOUNDARY
    protocol.py         length-prefixed JSON, MessageType, ErrorCode, limits
    transport.py        AF_UNIX / named pipe, no TCP, never pickle
    server.py           handshake, replay cache, worker threads, drain
    client.py           the thin in-child client (untrusted side)
  supervisor/           V2 EXTERNAL AUTHORITY
    daemon.py           WatcherDaemon: owns everything authoritative (1824 lines)
    session.py          SessionStateMachine
    storage.py          atomic trace/metadata persistence
    process_supervisor.py  the workload handle
  enforcement/          V3 OS CONTAINMENT
    base.py             Enforcer ABC, SandboxSpec, ContainmentUnit, select_backend
    capabilities.py     HostCapabilities, doctor_report, real probes
    profile.py          ContainmentProfile + PRESETS + digest + validate
    procfs.py           trusted-side /proc observation
    backends/namespaces.py   rootless userns backend (1051 lines)
    backends/docker.py       container backend (experimental, unverified)
    linux/landlock_ruleset.py, seccomp_filter.py, resource_limits.py, exec_guard.py
  runtime/process.py    LocalProcess, descendant_pids, terminate_tree
```

### 1.2 The decision path, end to end

This is the path V4 must not perturb. One request, one thread:

```
client: WatcherClient.evaluate(...)                      ipc/client.py:315
  -> encode_message / send_bytes                         ipc/protocol.py:450, ipc/transport.py:180
  -> recv_bytes(max_message_bytes=256KiB)                 ipc/transport.py:209
  -> decode_message: size, UTF-8, NUL, JSON, envelope,
     version==1, type, request_id, session_id,
     validate_payload (depth 6, string 4096, items 64)    ipc/protocol.py:235-320
  -> IpcServer._serve_one: session match, replay cache,
     _begin_write (writer claim)                          ipc/server.py:543-643
  -> WatcherDaemon.dispatch: shutdown/terminal gates       supervisor/daemon.py:1127-1185
  -> _handle_evaluate
       strip_authoritative_fields (recursive)             ipc/protocol.py:402-424
       re-validate, inject metadata["ipc"], take _lock    supervisor/daemon.py:1320-1374
  -> PoEWatcher.evaluate:                                 watcher/watcher.py:325
       1. killed? -> KILL, everything blocked             watcher/watcher.py:343-360
       2. TripwireRegistry.check -> KILL + activation     watcher/watcher.py:363-390
       3. Policy.evaluate: 11 ordered pure checks         watcher/policy.py:168-190
       4. quarantined + blocked -> escalate to KILL       watcher/watcher.py:396-403
       5. _record_decision -> POLICY_DECISION/DENIED      watcher/watcher.py:589-622
       6. _apply -> kill() / _quarantine()                watcher/watcher.py:624-659
  -> _decision_payload {decision, risk, reason, rule,
     session_state, killed}                               supervisor/daemon.py:1391-1399
  -> build_response -> send                                ipc/protocol.py:450
```

**Determinism verified on this path:** no model call, no network call, no `random`,
`secrets`, `uuid` or clock read participates in the *verdict*. The only
nondeterministic inputs are (a) the wall clock that stamps the event
(`poe/recorder.py:99`, clamped non-decreasing at `poe/trace.py:103-135`) and (b) the
client-supplied `metadata` facts listed in §3.2.

### 1.3 Authoritative state ownership

| State | Owner | Location |
|---|---|---|
| Clock | daemon | `supervisor/daemon.py:233`, propagated 248, 494-500, 571, 594 |
| Sequence numbers | `ExecutionTrace.append` only | `poe/trace.py:139-140` |
| Timestamps | `Recorder` under the same lock as append | `poe/recorder.py:96-108` |
| previous/event/final hashes | trace | `poe/trace.py:76-78, 175-197` |
| Session id | daemon | `supervisor/daemon.py:235` |
| Bearer token | daemon | `supervisor/daemon.py:485`; injected into child env at 899 |
| PoE writes | single funnel | `supervisor/daemon.py:1516-1535` |
| Kill switch | `PoEWatcher` | `watcher/kill_switch.py:105-135` |
| Policy / tripwires | construction-time only | `supervisor/daemon.py:252-253`, `watcher/watcher.py:249-258` |

**The guarantee that holds:** a client cannot supply `sequence`, `timestamp`,
`previous_hash`, `event_hash`, `final_hash`, `decision` or `risk`
(`ipc/protocol.py:115-125`, recursive strip at `402-424`).

### 1.4 Where containment sits

`select_backend` (`enforcement/base.py:365-411`) picks the first available of
`namespaces` → `docker` for `backend: auto`. Nothing available → raises
`EnforcementUnavailable`, caught at `supervisor/daemon.py:427-432`, exit code **78**,
**workload never started**. That fail-closed property is correct and must be preserved.

---

## 2. Reusable components

V4 is a build-on, not a rewrite. These are the components V4 should consume as-is.

### 2.1 Reuse verbatim

| Component | Why it is reusable |
|---|---|
| `poe/canonical.py` `normalise` / `canonical_json` / `canonical_bytes` / `sha256_hex` | Already the project's determinism substrate: sorted keys, `separators=(",",":")`, `ensure_ascii`, NaN/inf rejected (`canonical.py:62-68`), set ordering (`107-110`), depth cap (`44,50-53`). **Policy V1 digests and anchor hashes must be built on exactly this**, with a domain-separation prefix. |
| `poe/event.py` `PoEEvent` | Frozen dataclass; `hashed_payload()` includes `previous_hash` and excludes `event_hash` (`event.py:176-193`). V4 must not change the payload key set — see §11.2. |
| `watcher/decision.py` `Decision`, `Risk`, `max_decision`, `max_risk` | The severity lattice (`decision.py:30-52`) is exactly the algebra the policy resolver needs for `on_violation` merging. `Decision`/`Risk` stay frozen as public enums. |
| `watcher/decision.py` `Evaluation` | Already carries `reason` + `rule` + `tripwire_id` and an `escalate()` that can only strengthen (`decision.py:93-101`) — the seed of `DecisionReason`. |
| `watcher/matching.py` | Path component matching (`path_is_within`, `57-65`) and domain globs incl. `*.` (`113-125`) are correct; V4 extends rather than replaces. See §4.4 for the `**` gap. |
| `enforcement/profile.py` `ContainmentProfile.digest()` | The existing precedent for a configuration digest over `canonical_bytes(to_dict())` (`profile.py:366-373`). V4 mirrors this pattern and fixes its one weakness (no version/domain separation). |
| `enforcement/capabilities.py` `HostCapabilities` + `doctor_report()` | A real probing layer with `AVAILABLE`/reason reporting (`capabilities.py:62-71, 168-243`). V4 extends it; it does not invent a new one. |
| `enforcement/base.py` `Enforcer.isolate_network` | The teardown-time network hook **already exists and is already wired** (`base.py:330-332`, called from `supervisor/daemon.py:807-820`). V4 network work plugs in here. |
| `supervisor/storage.py` `_atomic_write` | temp + `O_EXCL` + `fsync` + chmod 0600 + `os.replace` (`storage.py:78-102`). Reuse for the anchor file; add the missing parent-directory fsync. |
| `ipc/server.py` `_begin_write` | The single admission-control choke point for every request (`server.py:645-657`). **This is where rate limiting belongs.** |
| `ipc/protocol.py` `AUTHORITATIVE_FIELDS` + `strip_authoritative_fields` | An allow/deny discipline that already works and is tested (`test_ipc_protocol.py:327-393`). |
| `tests/conftest.py` `DaemonHarness`, `FakeClock`, `requires_enforcement()` | Real-daemon-in-thread harness, deterministic clocks, honest skip reasons. V4 tests build on these. |

### 2.2 Extend, do not replace

| Component | Required extension |
|---|---|
| `watcher/matching.py` | Add explicit glob support (`*`, `**`, `?`) with validation; reject unsupported syntax. §4.4. |
| `watcher/policy.py` | Keep `Policy` frozen for V3 compatibility; add `Policy V1` as a **sibling** model with a deterministic projection onto `Policy`. §4, §11.3. |
| `enforcement/capabilities.py` | Prove cgroup **delegation** by actually creating a cgroup, not by `os.path.exists`. §9. |
| `enforcement/backends/namespaces.py` | Replace the two `network=restricted` refusals (`168-176`, `docker.py:87-91`) with the implemented design, or keep refusing. §8. |
| `enforcement/base.py` | Add a cgroup path to `SandboxSpec`; use `cgroup.events populated=0` in `verify_empty`. §9. |
| `poe/verifier.py` | Add separate anchor verdicts alongside `valid`. §10. |
| `supervisor/daemon.py` | Fix the orphan-on-abnormal-exit defect (§3.1); call the rate limiter at the existing choke point. §6. |
| `cli.py` | Add a `policy` subcommand group; keep all five existing subcommands and their flags/exit codes byte-compatible. §11.4. |

### 2.3 Do not touch

`poe/trace.py` chain construction, `poe/event.py` payload shape,
`watcher/watcher.py` evaluation order (killed → tripwire → policy → quarantine),
`ipc/protocol.py` framing and limits, `ipc/transport.py`, and the
`supervisor/daemon.py` drain-before-seal sequencing. These are the parts that are
correct and heavily tested; V4 composes around them.

---

## 3. Technical debt and risks

Findings are grouped by severity. Every one is cited.

### 3.1 Correctness / security defects to fix in V4

**R-1 — `_finalize` never terminates the workload; the trace then records an exit that did not happen.** *(highest severity)*
`supervisor/daemon.py:1539-1666` destroys containment, drains IPC, records, seals and
writes — but `terminate_tree` appears nowhere in it (only at `daemon.py:1086`, in kill
accounting). The `except Exception` handler at `437-439` then calls
`_finalize(1)` at `442`. Result: a Ctrl-C or an internal error after `Popen` leaves a
process that is **fully detached** (POSIX `start_new_session=True`,
`runtime/process.py:192`) while the trace records
`PROCESS_EXITED ... "protected process exited with 1"` (`1594-1608`) and metadata
records `exit_code: 1, status: FAILED` (`1739-1745`). V1 gets this right
(`watcher/watcher.py:167-179`); the supervisor does not. There is also **no signal
handler** anywhere in the daemon or CLI, so SIGTERM loses the entire in-memory trace.
*Severity: high. This is a false audit record, which is the one thing this project
exists to prevent.*

**R-2 — Client-asserted facts drive policy decisions.**
`Policy` reads `metadata` supplied by the client for `privilege_escalation`
(`policy.py:199`), `host_resource` (`235`), `persistence` (`257`), `path`
(`283`, `320`), `env_var` (`300`), `domain` (`357`), `tool` (`393`),
`process_count` (`423`), `runtime_seconds` (`451`). Note `meta["path"]` **overrides**
`resource` at `320`, so a path check can be aimed at a benign path. The engine is
deterministic; the facts are unverified assertions. Additionally the daemon never
calls `report_process`/`report_signal`, so the process, runtime and host-signal rules
are effectively dead under V2/V3 IPC mode.
*Severity: high. This is the single most important honesty item for V4: without SDK
instrumentation or OS-level observation, most policy rules do not fire. §7.4 states
what zero-code mode actually enforces.*

**R-3 — Authentication is a bearer token with no peer identity, while an unverified client-claimed PID enters the PoE.**
`server.py:508` sets `context.client_pid = payload.get("pid")`; that value is recorded
as `client_pid` (`daemon.py:1371, 1388, 1412`). There are no peer credentials
(`SO_PEERCRED`, `LOCAL_PEERPID`, `GetNamedPipeClientProcessId`) anywhere, no nonce, no
challenge-response, and no transport `authkey` (`transport.py:265`). The token sits in
the child's environment (`daemon.py:899`), readable by any same-user process.
*Severity: high for audit fidelity* (any token-holder can write any PID into the
evidence record), *medium for containment* (requires same-user token read).

**R-4 — The `valid` verdict is a self-consistency check, not authenticity.**
`verifier.py:160-164` compares `declared_final_hash` against a value recomputed from
the same file, and `declared_final_hash` is itself read from that file
(`trace.py:304-306`). An attacker with write access to
`<root>/sessions/<id>/trace.json` edits events, calls `relink(0)`
(`trace.py:199-221`), re-seals (`trace.py:194-197`) and writes back: `watcher verify`
exit **0**, `tampered` false. This is documented honestly
(`trace.py:199-207`, `README.md:232-235`) and is what §10 fixes.
*Severity: high — it is the gap V4's anchor exists to close.*

**R-5 — Tail truncation and unsealed traces are not detected.**
`verifier.py:161` skips the final-hash check when the JSON has no `final_hash`. An
attacker who deletes that key and truncates the tail gets `valid`. Related:
`ExecutionTrace(...).verify()` on an empty trace returns valid (the loop body never
runs), asymmetric with `verify_dict`, which rejects empty (`verifier.py:187-194`).
`README.md:230-231` ("deleting ... breaks verification at that point and at every
point after it") is therefore conditional and must be qualified.
*Severity: medium-high.*

**R-6 — `verify_empty` uses a single namespace inode and is not a sound emptiness proof.**
Identity is one inode, user-namespace preferred (`namespaces.py:1032-1040`,
`base.py:338-349`). A process that calls the **legacy `clone`** (no `clone` entry in
any seccomp table — `seccomp_filter.py:81-194`) lands in a child user namespace that
shares the PID namespace but has a different `ns/user` inode, and is invisible to the
check. `inspect()` also **overwrites `unit.namespaces` with `{}`** for a dead pid
(`namespaces.py:762`), after which `verify_empty` sees no namespace and returns
`(False, [])` — producing a spurious `KILL_FAILED`/CRITICAL event
(`daemon.py:845-862`).
*Severity: medium-high.*

**R-7 — Declared-but-not-enforced configuration overstates the posture.**
`resources.cpus` (default `1.0`, `profile.py:208`) is never enforced by the namespaces
backend — the only consumer is `docker.py:129-130` — yet it is printed by
`summary()` (`profile.py:465`) and included in the profile digest.
`drop_all_capabilities`, `add_capabilities` and `no_new_privileges` are **read by no
backend or guard**: `drop_capabilities()` always drops everything
(`exec_guard.py:174-213`) and `no_new_privs` is always set (`seccomp_filter.py:324-326`).
So `no_new_privileges=False` is recorded as reduced protection while the kernel
enforces `nnp=1`, and a permitted `add_capabilities=("CAP_NET_BIND_SERVICE",)`
(sanctioned by `profile.py:390-401`, tested at `test_v3_profile.py:201-205`) is
silently dropped.
*Severity: medium — but it is exactly the class of dishonesty V4 must eliminate.*

**R-8 — Verification gates skip on absent keys rather than failing.**
`if landlock and not landlock.get("enabled")` (`namespaces.py:827-830`): a guard
reporting `"landlock": {}` yields no problem. Same shape at `832-834` for
capabilities. Fail-open-shaped verification logic.
*Severity: medium.*

**R-9 — `_read_report` framing stops at the first `}`.**
`namespaces.py:703-736` reads until a chunk contains `b"}"`; a brace inside a problem
string truncates the JSON → parse error → `ContainmentStartError`. Fail-closed, but
flaky (`375-383`).
*Severity: low-medium.*

**R-10 — Double close of `write_fd` on the start-failure path.**
`namespaces.py:328-338`: the `except` closes `write_fd` at `332`, the `finally` closes
it again at `338` → `OSError(EBADF)` from the `finally` masks the real start error,
and the second close can hit an fd recycled by an IPC thread.
*Severity: low-medium.*

**R-11 — Shared, fixed, world-writable scratch paths.**
`SCRATCH_BASE`/`SCRATCH_INNER`/`CONTROL_DIR_INNER` (`namespaces.py:77-80`) are global,
not per-unit, created with `os.makedirs(..., mode=0o700, exist_ok=True)` under `/tmp`
without `lstat`/`O_NOFOLLOW`/ownership checks (`597-621`); `_install_guard` follows
symlinks the same way (`427-445`). Concurrent sessions collide on these paths.
*Severity: medium on multi-user hosts.*

**R-12 — Validation-then-use TOCTOU across prepare → launch → guard.**
Paths are resolved at `prepare` (`_validate_spec` `250-279`), re-resolved at `launch`
(`_resolve_layout` `508`, `_mount_plan` `588`), and again in the guard
(`exec_guard.py:133-145`). Nothing pins the workspace inode across the boundary. Also
`control.startswith(workspace + os.sep)` (`264-273`) misses `workspace == "/"`.
*Severity: medium, small window.*

**R-13 — `_probe_seccomp` forks inside a possibly multi-threaded supervisor and hardcodes x86_64.**
`capabilities.py:270-293` uses `os.fork()` and ctypes in the child, with a pipe read
that has **no timeout**; `probe_path_access` deliberately uses a subprocess for this
reason (`landlock_ruleset.py:361-363`). And `_AUDIT_ARCH_X86_64` is hardcoded
(`capabilities.py:38, 262-263`): on aarch64 the probe child is killed by the arch
check, so seccomp is reported unavailable and the namespaces backend is reported
unavailable — even though `seccomp_filter.py` has a correct aarch64 table.
*Severity: medium (correctness of `doctor` on non-x86).*

**R-14 — The client can serialize the daemon lock and grow the trace without bound.**
`_handle_evaluate` holds `self._lock` across `evaluate()` → possible `kill()` →
`terminate_tree()` (`daemon.py:1191-1202`; `runtime/process.py:337-345, 388-394`
where Windows `taskkill` gets `max(5.0, grace*2)`). One KILL can stall every other
request for seconds. Separately there is **no event cap and no byte cap** on the
in-memory trace (`poe/trace.py:58`), and each request can append 1-3 events of up to
256 KiB — a client can OOM the supervisor before it seals.
*Severity: medium-high (availability / DoS).*

**R-15 — Replay cache races and is a FIFO, not a nonce.**
`server.py:664-674` is check-then-set with **no lock** across up to 4 worker threads,
and the cache is a 4096-entry FIFO, so an old `request_id` becomes replayable after
4096 newer requests. HELLO never enters the cache. Counters at `458, 551, 587` are
incremented unlocked.
*Severity: medium.*

**R-16 — Storage failure is swallowed and does not change the exit code.**
`daemon.py:1653-1657` catches `Exception` into `_internal_error`; `run()` still
returns `_exit_code` (`449-453`). A clean `0`-exit run whose PoE was never persisted.
Same for `trace_out` (`1659-1666`). Combined with the trace being in-memory-only until
finalization, a SIGTERM or OOM loses the entire evidence record.
*Severity: medium-high for the product's core promise.*

**R-17 — Hook failures silently erase audit events.**
`server.py:678-685` swallows every exception from the hooks; a failed
`on_client_authenticated` leaves no event while authentication still succeeds
(flag set at `506`, hook called at `517`), and a failed `session_snapshot` silently
reports `state="RUNNING"` (`518-529`).
*Severity: medium.*

**R-18 — Small dead/incorrect knobs.** `block_kexec` is unreachable
(`CATEGORY_FLAGS["kexec"]` at `seccomp_filter.py:211` has no matching table entry;
the special case at `266-267` is dead). `block_swap` is never consulted (`swap` maps
to `block_raw_io` at `206-207`). `SyscallPolicy.profile` is a label only. `_SAFE_CLIENT_FIELDS`
is duplicated and unused (`daemon.py:111`). `IpcLimits.validate` checks 4 of 9 fields
(`protocol.py:173-181`); `idle_poll<=0` hot-spins (`transport.py:243-246` +
`server.py:452-454`). `NAMESPACES_CREATED` is recorded with a hardcoded
`"user,pid,mnt,ipc,uts,net"` even when `--net` was not passed (`daemon.py:708-711`).
*Severity: low, but each is a false statement in the trace or a footgun.*

### 3.2 Process and lifecycle gaps

**R-19 — No server-side request deadline.** `IpcLimits.request_timeout`
(`protocol.py:168`) is used only by the client (`client.py:154, 315`). A peer that
sends a partial length prefix blocks a worker in `recv_bytes` indefinitely, and there
are only 4 connection slots.

**R-20 — Client-controlled detection bypass.** `_client_said_goodbye`
(`daemon.py:1303-1316`) suppresses the IPC_LOST alarm in **both** detection paths
(`940-941`, `1454-1473`). Defaults are `record` for both `heartbeat_action` (`159`)
and `ipc_lost_action` (`162`), and the CLI defaults match (`cli.py:156, 169`). A
workload can send SESSION_END and then keep running unsupervised.

**R-21 — Pre-spawn IPC window.** The server accepts and authenticates
(`daemon.py:565-572`) before the child exists (`588-596`). A KILL_REQUEST in that
window engages the kill switch with `local_process=None` (`1041-1045`) without setting
`_quit` (`1295`), after which the workload is spawned anyway and never killed.

**R-22 — `_control_dir` keyed by `session_id[:12]`.** Two operator-named colliding
sessions bind the same socket path and one session's cleanup `rmtree`s the other's
directory (`daemon.py:630-632`, `transport.py:121-145, 307`). A pre-existing path is
trusted via `os.makedirs(exist_ok=True)` with no ownership or mode check.

**R-23 — Kill-tree gaps.** Windows depends on `taskkill /T /F` and honestly records
`tree_enumerated=False` when it fails (`runtime/process.py:409-432`), but detached
descendants survive while the session reports KILLED. POSIX `killpg` + ppid walk
(`337`, `115-141`) miss a `setsid()`/double-forked child.

**R-24 — Uncaught exceptions in the CLI.** `ContainmentRefused` is not caught around
profile load or `validate()` (`cli.py:506-520` catches only
`FileNotFoundError`/`OSError`/`ValueError`; the error is raised at `profile.py:287, 380`),
so a bad profile yields a traceback and exit 1 instead of a clean message and exit 2.
`storage.read_trace` is called outside the `try` in `cmd_status` (`cli.py:661-662`),
and `verify_file` catches only `(OSError, TraceError)` (`verifier.py:198-209`), so a
trace with a non-numeric `created_at` (`trace.py:302`) raises out of `watcher verify`.

**R-25 — Redaction coverage is narrower than the README claims.**
`Recorder.record` redacts only `resource` and `metadata`
(`recorder.py:100-107`); `action` and `reason` pass through untouched, and the
daemon's `_scrub` only removes the session token (`daemon.py:1503-1514`). A credential
placed in `action` or `reason` reaches `trace.json` in cleartext, contradicting
`README.md:528-532` ("Secrets never reach the trace").

**R-26 — Documentation claims requiring correction in V4.** Beyond R-7/R-25:
`README.md:39` ("observe every attempted action, before it happens") — the supervisor
only learns about client-mediated actions; there is no syscall auditing and
`SECCOMP_RET_USER_NOTIF` is explicitly not used (`seccomp_filter.py:21-27`).
`README.md:240-241` lists a "duplicate hash" signal that does not exist in
`TamperSignal` (`verifier.py:31-42`). `README.md:442-450` omits exit codes `1` and `2`.
`README.md:491-495` advertises the `research-net` preset, which the only viable
backend refuses (`namespaces.py:168-176`).

### 3.3 Structural constraints V4 must respect

**C-1 — The event payload key set is frozen.** `tests/test_v2_boundaries.py:374-396`
asserts `set(event.to_dict())` is exactly 11 keys and
`schema_version == "watcher-poe/1"`. **Adding `policy_digest` as an event *field* would
break this.** Consequence for §4.7: the policy digest must live inside the hashed
`metadata` mapping, not as a top-level event field.

**C-2 — README ⇄ CLI consistency is tested, but the regex is narrow.**
`tests/test_packaging.py:174-187` extracts
`watcher (run|status|verify|demo|doctor)` from the README and asserts each is a real
subcommand. A **new** `policy` subcommand documented as `watcher policy validate` is
not matched by this regex, so it will not be caught. V4 should widen the regex to
include `policy` so the guard keeps working in the direction it was intended.

**C-3 — Zero runtime dependencies is a tested contract.**
`pyproject.toml:20-21` and `tests/test_packaging.py:28-66`. **No PyYAML.** This drives
§4.9.

**C-4 — Flags, defaults and exit codes are effectively public API.**
Exit codes: `0` ok, child's own code, `1` doctor/verify/status/demo failure, `2` CLI
misuse, `124` inline timeout, `137` killed, `78` enforcement refused
(`cli.py:34-35, 376-382`; `daemon.py:103, 449-453`). Defaults that must not drift:
`--fail-mode fail_closed` (`cli.py:426`), `--ipc-timeout 5.0` (`430`),
`--heartbeat-interval 5.0` / `--heartbeat-timeout 30.0` / `--heartbeat-action record`
(`432-434`), `--ipc-lost-action record` (`435`), `--containment-profile research-strict`.
`--enforced` + `--inline` must stay an error (`cli.py:353-359`).

**C-5 — `the_watcher.Decision` is a public enum.** Any V4 object named `Decision`
must not shadow it. See ODD-1 in §16.

**C-6 — V3 CLI flags are silently ignored without `--enforced`.**
`_build_containment_profile` is only called when `enforced` is true
(`cli.py:419-420`). `watcher run --memory 512 --python x.py` without `--enforced` is
accepted and ignored. V4 should warn, not fail (behaviour change), or document it.

---

## 4. Proposed Policy V1 schema

### 4.1 Goals and non-goals

**Goals:** strict validation; unknown keys rejected; deterministic normalization;
canonical representation; a digest recorded in the PoE; human-readable errors; **no
silent coercion**.

**Explicit method for "no silent coercion":** every acceptance decision is *either* an
exact, documented match *or* a hard error. There is no code path that coerces a value
into a valid one. Specifically rejected rather than coerced: `"1"` for `version`,
`"30"` for an integer limit, `"true"` for a boolean, `"ALLOW"` in `on_violation`, a
path with unsupported glob syntax, a duplicate counter specified via two spellings,
and a non-string list element.

### 4.2 Document shape

```yaml
version: 1
name: project-default            # optional, informational, part of the digest

filesystem:
  allow:
    - /workspace/**
  deny:
    - /etc/**
    - ~/.ssh/**

network:
  mode: restricted               # none | restricted | open
  allow:
    - api.openai.com
    - api.deepseek.com
  deny:
    - metadata.google.internal

process:
  max_children: 8
  max_runtime_seconds: 600

rate_limits:
  shell_commands:
    per_minute: 30
    per_session: 1000
  network_requests:
    per_minute: 100
  file_writes:
    per_minute: 200

resources:
  memory_mb: 1024
  cpu_seconds: 600
  pids: 32

tripwires:
  - ~/.ssh/id_rsa
  - /var/run/docker.sock

on_violation:
  forbidden_file: DENY
  tripwire: KILL
  rate_limit: QUARANTINE
  resource_limit: QUARANTINE
  network: DENY
  process_limit: DENY
```

### 4.3 Section-by-section rules

**`version`** — required, JSON integer, exactly `1`. `"1"`, `1.0` and absent are all
errors. An unknown version is rejected with the supported list. This field is what
makes `watcher run --policy` able to dispatch deterministically between Policy V1 and
the legacy V3 `Policy` (§11.3).

**`name`** — optional string, 1-64 chars, `[A-Za-z0-9._-]`. Informational; included in
the digest so that two documents differing only by name have different digests.

**`filesystem.allow` / `filesystem.deny`** — lists of path patterns. Normalization
(§4.4) then validation. Unknown sub-keys rejected. A pattern that normalizes to the
empty string is an error, not a no-op.

**`network.mode`** — required when the `network` section is present; one of
`none | restricted | open`. `allow` is only meaningful with `restricted`; a document
that sets `allow` with `mode: none` is an **error** (an unsatisfiable, self-
contradictory declaration that would otherwise be silently ignored). `deny` is
meaningful in every mode.

**`network.allow` / `network.deny`** — list of hostnames. Normalized to lowercase,
trailing root dot stripped, IDNA-encoded to A-label form, validated against an
RFC-1123 hostname grammar. Leading `*.` is permitted and means "this domain and any
subdomain" (matching the existing `domain_matches`, `matching.py:113-125`). An IP
literal, a CIDR, a URL with a scheme, or a host with a port is an **error** with a
pointed message: V3's containment profile uses CIDRs (`profile.py:475`) and V4's
policy uses names; confusing the two silently would be exactly the sort of coercion
this schema forbids.

**`process.max_children`** — integer ≥ 0. `max_runtime_seconds` — integer > 0.

**`rate_limits.<counter>`** — a mapping of scope → integer ≥ 0, or the flat shorthand
(§4.5). Scope keys are `per_second`, `per_minute`, `per_session`. Counter names are a
closed vocabulary (§6.2). Unknown counter or scope keys are errors.

**`resources.memory_mb`** — integer ≥ 16. `cpu_seconds` — integer > 0.
`pids` — integer ≥ 1. Absent means "no ceiling from this layer".

**`tripwires`** — a list of paths (glob rules as §4.4) or a list of expanded tripwire
objects. The path shorthand is equivalent to a full tripwire with
`decision: KILL`, `risk: CRITICAL`, `event_types` covering file access, file
modification, shell command and process creation, and `id` derived deterministically
from the normalized path (so the digest is stable and the PoE shows a stable id).
Mixing shorthand strings and objects in one list is permitted; the resolved form is
canonical either way.

**`on_violation`** — maps a violation class to a decision. The class vocabulary is
closed: `forbidden_file`, `tripwire`, `rate_limit`, `resource_limit`, `network`,
`process_limit`. The decision vocabulary here is **`DENY | QUARANTINE | KILL`** —
`ALLOW` is rejected, because `on_violation: {tripwire: ALLOW}` would disable a
mandatory rule through a misreading of the field name. Missing classes default to the
baseline value declared by the Watcher baseline layer, which V4 documents once and
freezes.

### 4.4 Path patterns, normalization and the `**` gap

**This is a defect to fix, not a design preference.** V3's matcher
(`matching.py:57-73`) has no glob support at all: `path_is_within("/workspace/a.txt",
"/workspace/**")` is `False`, because `**` is treated as a literal path component.
So the V4 example policy above — and the one in the mission brief — would **silently
deny nothing** under V3 semantics. `normalise_path` (`matching.py:33-54`) does not
special-case `*` either.

Policy V1 therefore defines glob semantics explicitly, and `**` becomes real:

| Pattern form | Meaning in Policy V1 | V3 engine behaviour today |
|---|---|---|
| `/etc` | exactly `/etc` **or any descendant** | same (implicit subtree, `matching.py:57-65`) |
| `/etc/**` | exactly `/etc` or any descendant | **matches nothing** (V3 reads `**` as a literal segment) |
| `/etc/*` | `/etc` plus exactly one further segment | literal (`*` as a filename char) |
| `/etc/?asswd` | single character in a segment | literal |
| `~/.ssh/**` | `~` expanded against the resolution base, then subtree | expansion exists (`matching.py:45`), glob does not |

**These are Policy V1's semantics, and they are not a change to V3's runtime.**
Policy V1 is a new document format in a new module and is **not runtime-wired**:
`watcher run --policy` still loads the existing V3 policy JSON and still evaluates
it with V3's matcher and evaluator. So at runtime today `/etc/**` continues to
match nothing and `/etc/*` continues to be a literal — exactly what the third
column says. Nothing in this section alters what V3 enforces. **V3 runtime
semantics are unchanged**; these semantics take effect only when a later phase
projects Policy V1 onto the runtime.

Design rules:

1. **Bare paths keep V3's implicit-subtree semantics.** This is deliberate: it is
   backward compatible and it matches operator intent, and the alternative (exact-only)
   would *weaken* existing policies — a silent relaxation, which the project must never
   do.
2. **`**` is implemented and is exactly equivalent to the implicit subtree.** Resolving it
   makes the rule behave as written instead of as a literal. The *direction* of that
   change depends on the rule, so "can only strengthen" would be too strong as a blanket
   claim: for a `deny` rule the resolved form restricts more, while for an `allow` rule it
   permits more than today's match-nothing reading. The phase that projects Policy V1 onto
   the runtime must argue that direction rule by rule. Here it has no runtime effect at
   all, because the format is not runtime-wired (see the note above).
3. **Unsupported glob syntax is a validation error at parse time, never a literal.**
   `[abc]`, `{a,b}`, `!(...)`, a `**` in the middle of a segment (`/a/**/b` — supported
   only as a whole trailing segment or a whole middle segment; the *segment* form
   `/a/**/b` **is** supported and means "zero or more segments"), and any pattern
   containing a NUL are rejected with a message naming the offending character and
   position. This is the "no silent coercion" rule applied where it matters most: a
   glob the engine does not understand must never quietly match nothing.
4. **A conformance test asserts that every glob in the documented example matches at
   least one witness path and fails at least one non-witness.** A pattern that matches
   nothing anywhere in the test corpus is a test failure. This is what would have
   caught the `**` gap.

**Normalization is platform-independent — and this is a change from V3.**
`matching.py:52-53` lower-cases paths on Windows (`if _IS_WINDOWS: text = text.lower()`),
so the *same* policy and the *same* event yield different decisions on Windows and
Linux. That directly violates V4's core invariant ("same normalized request + same
resolved policy + same state = same decision") in a cross-platform sense. V4's Policy
V1 normalization therefore:

- does **not** case-fold, on any platform;
- expands `~` and `$VAR` only against an explicit, declared resolution base supplied by
  the resolver, and records the base in the resolved policy and its digest;
- rejects a pattern using `$VAR` when no value is defined in the resolution
  environment (rather than `os.path.expandvars`' silent pass-through,
  `matching.py:46`);
- records filesystem case-sensitivity as an explicit, policy-visible property
  (`case_sensitive: true|false|auto` with `auto` resolving to a recorded concrete
  value), so that intent is expressed rather than platform behaviour being assumed.

This is a **behaviour change on Windows** for legacy V3 policies. §11.3 explains how it
is contained.

### 4.5 Canonical form and the two digests

Two normative canonical forms, both built on `poe/canonical.py`:

- **Policy document (one layer as authored).** Platform-independent normalized form:
  patterns as written (glob syntax validated, whitespace trimmed), lists
  **sorted and de-duplicated**, mappings key-sorted by `canonical_json`, domains
  A-label lowercase, integers as integers. Digest:

  ```
  policy_document_digest =
      sha256_hex(b"the-watcher/policy-document/1\x00" + canonical_bytes(normalized))
  ```

- **Resolved policy (after layering and resolution).** All bases expanded, all
  inheritance folded, provenance and conflicts included. Digest:

  ```
  resolved_policy_digest =
      sha256_hex(b"the-watcher/policy-resolved/1\x00" + canonical_bytes(resolved))
  ```

**Why the domain-separation prefix matters.** Without it, a policy digest could equal
an event hash or a bare payload digest, and a digest is compared in security decisions
and in anchor verification. Prefixing with a domain string makes cross-protocol
collisions meaningless. The existing `ContainmentProfile.digest()`
(`profile.py:366-373`) omits both a version and a domain prefix; V4 mirrors the
pattern but fixes that, and `policy-resolved/1` is versioned so a future merge
algorithm change cannot silently produce a digest that looks comparable.

**Both digests are recorded.** `policy_document_digest` per layer (so an audit can say
*which organization policy* was in force) and `resolved_policy_digest` once per session
(so a decision is bound to the exact effective rule set). Recorded inside the hashed
`metadata` of the authoritative lifecycle events — see §4.7 and C-1.

### 4.6 Human-readable validation errors

`PolicyValidationError` carries a list of `PolicyIssue`s, each with a JSON Pointer
path, a machine code, and a sentence. Example rendering:

```
watcher policy validate watcher.yml

watcher.yml: FAILED (3 issues)

  1. /filesystem/deny/0: unsupported glob syntax '[' at character 5.
       '/etc/[abc]' is not a supported pattern. Policy V1 supports '*' (within a
       segment), '**' (zero or more segments) and '?' (one character).
       Unsupported patterns are rejected rather than treated literally, because a
       rule that matches nothing looks identical to a working rule.

  2. /network/allowed_networks: unknown key. Did you mean 'allow'?
       'allowed_networks' is a containment-profile field (CIDRs). Policy V1 uses
       'network.allow' with hostnames. See docs/policy.md#network.

  3. /on_violation/tripwire: 'ALLOW' is not permitted.
       A tripwire is mandatory and cannot be downgraded to ALLOW. Permitted
       values: DENY, QUARANTINE, KILL.
```

Requirements: every error names the exact JSON Pointer; a near-miss key produces a
`did you mean` suggestion (Levenshtein, deterministic tie-break by lexical order); all
issues are reported, not just the first (so a review is one pass, not ten); the exit
code is `2` (CLI misuse, matching the existing convention at `cli.py:514, 520`); and
the same issues are available as structured JSON via `--json`.

### 4.7 Recording the digest in the PoE

**Constraint C-1** forbids adding an event field: `tests/test_v2_boundaries.py:374-396`
pins the event payload to exactly 11 keys and `schema_version` to
`"watcher-poe/1"`. V4 keeps both and records digests inside `metadata`, which is
already part of `hashed_payload()` (`poe/event.py:176-193`) and therefore already
covered by the chain and by `compute_final_hash()`:

- `SESSION_START` metadata: `policy_version`, `resolved_policy_digest`,
  `policy_layers: [{level, name, digest}]`, `policy_conflicts: [...]`,
  `engine_version`.
- Every `POLICY_DECISION` metadata: `rule`, `resolved_policy_digest`, and for a
  rate-limit decision the full §6.5 record.
- A `POLICY_RESOLVED` event (§6.1) at session start, so the resolution is legible on
  its own.

Because `compute_final_hash()` covers the final event hash transitively, and the anchor
covers `compute_final_hash()`, the policy identity becomes **anchored** — a property
the current `metadata.json`-only approach cannot provide, since `metadata.json` is not
covered by any hash (R-4).

### 4.8 Legacy projection

Policy V1 is a superset of V3 `Policy`. The resolver projects a resolved policy onto an
existing `Policy` instance so that `PoEWatcher` needs no change:

| Policy V1 | V3 `Policy` field |
|---|---|
| `filesystem.allow` (patterns) | `allowed_paths` |
| `filesystem.deny` | `forbidden_paths` |
| `network.allow` | `allowed_domains` |
| `network.deny` | `forbidden_domains` |
| `network.mode == none` | `restrict_network = True`, `allowed_domains = ()`, and the empty-netns containment posture |
| `network.mode == restricted` | `restrict_network = True` |
| `network.mode == open` | `restrict_network = False` |
| `process.max_children` | `max_processes` |
| `process.max_runtime_seconds` | `max_runtime_seconds` |
| `tripwires` (paths) | `TripwireRegistry` entries |
| `on_violation.*` | the decision returned by the corresponding rule |

The projection is total and deterministic, and a test asserts
`project(resolve([doc]))` equals the hand-written V3 `Policy` for the equivalent
configuration.

### 4.9 File format — JSON normative, YAML subset second (ODD-3)

`pyproject.toml:20-21` and `tests/test_packaging.py:28-66` make zero runtime
dependencies a tested contract, so PyYAML is out. The mission example is YAML, so this
needs a decision:

- **JSON is the normative on-disk format**, and the digest is *always* computed over
  canonical JSON regardless of source syntax. This means one file cannot produce two
  digests depending on how it was parsed.
- A **strict YAML-subset reader** (block mappings, block sequences, plain and
  double-quoted scalars, integers, booleans, comments; **no** anchors, aliases, tags,
  multi-document streams, flow collections, block scalars or merge keys) is a separate
  deliverable with its own conformance suite. Anything outside the subset is a hard
  error with a line number — never a guess.
- Recommendation in §16 (ODD-3): ship JSON-only in Phase 1, land the YAML subset in
  Phase 2 after the parser-ambiguity suite exists. The mission's own hardening list
  names "policy parser ambiguity" as a risk, and a hand-rolled YAML parser is the
  single largest new attack surface V4 would introduce.

### 4.10 Schema summary (normative key list)

```
version*            int, == 1
name                str
filesystem          {allow[], deny[]}
network             {mode*, allow[], deny[], case_sensitive}
process             {max_children, max_runtime_seconds}
rate_limits         {<counter>: {per_second, per_minute, per_session}}
                    | {<counter>_per_(second|minute|session): int}   # documented shorthand
resources           {memory_mb, cpu_seconds, pids}
tripwires           [str | TripwireObject]
on_violation        {<violation_class>: DENY|QUARANTINE|KILL}
```
`*` = required. Unknown keys at **every** level are rejected.

---

## 5. Policy layering algorithm

### 5.1 Objects

```
PolicyLevel        enum: BASELINE < ORGANIZATION < PROJECT < SESSION
PolicyLayer        level, name, source_path, document, document_digest
PolicyConflict     kind, field, layers[], values[], resolution, severity
ResolvedPolicy     rules + provenance + conflicts + resolved_policy_digest
                   + project() -> watcher.policy.Policy
PolicyResolver     resolve(layers, base) -> ResolvedPolicy
```

**Precedence order is fixed by `PolicyLevel`, not by input order.** The resolver sorts
layers by `(level, name)` with a lexical tie-break, so the resolved digest is
independent of the order the caller supplied them in. More than one layer at the same
level is an error (ambiguous authority) unless the levels are explicitly declared
multi-instance — V4 Phase 1 rejects duplicates, which is the fail-closed choice.

### 5.2 The critical rule

> A lower layer MUST NOT weaken a stronger upper-layer restriction.

This is implemented as **a single monotone merge lattice**, not as a sequence of
special cases. Every field has a declared merge operator from this closed set:

| Operator | Meaning | Used by |
|---|---|---|
| `UNION` | permitted set grows (restriction grows) | `deny` sets, `tripwires` |
| `INTERSECT_UNIVERSE` | permitted set shrinks; a layer that declares nothing contributes the universal set | `allow` sets |
| `MIN` | tighter numeric ceiling wins; absent = +∞ | `process.*`, `rate_limits.*`, `resources.*` |
| `MAX_DECISION` | more severe decision wins (`watcher/decision.py:45-47`) | `on_violation.*` |
| `LATTICE_MIN` | least permissive mode wins | `network.mode` |
| `AND` | permitted only if every layer permits | boolean permissions |
| `KEYED_UNION` | per-key merge, recursively | nested mappings |

All seven operators are **commutative and associative**, which is what makes the
resolved digest order-independent. A property test asserts that every permutation of
the same layer set produces the same `resolved_policy_digest` (§13).

### 5.3 Worked examples from the brief

**Example 1 — the one in the brief.**

```
Organization: filesystem.deny: ["~/.ssh/**"]
Session:      filesystem.allow: ["~/.ssh/**"]
```
`deny` merges by `UNION` → `{ ~/.ssh/** }`. `allow` merges by `INTERSECT_UNIVERSE` →
`{ ~/.ssh/** } ∩ universal = { ~/.ssh/** }`. Evaluation order is **deny first**
(§5.4), so the result is `DENY`. ✔ The deny remains authoritative — the allow never
gets a chance to be consulted.

**Example 2 — network cannot be opened downstream.**

```
Organization: network.mode: restricted, allow: [api.openai.com]
Session:      network.mode: open
```
`LATTICE_MIN(none=0 < restricted=1 < open=2)` → `restricted`. ✔

**Example 3 — a ceiling cannot be raised downstream.**

```
Organization: process.max_children: 8
Project:      process.max_children: 64
```
`MIN` → `8`, and a `PolicyConflict(kind=CEILING_RAISED, severity=RECORDED)` is emitted
naming both layers, both values, and the resolution. The value is clamped, never
raised, and the attempt is visible in the PoE. ✔

**Example 4 — a tripwire cannot be removed or downgraded.**

```
Organization: tripwires: ["/var/run/docker.sock"]
Session:      tripwires: []                      # removal attempt
Session:      on_violation: {tripwire: DENY}     # downgrade attempt
```
`tripwires` merges by `UNION`, so the first is a no-op *and* raises
`PolicyConflict(kind=MANDATORY_RULE_WEAKENING, severity=REFUSED)`. The second merges
by `MAX_DECISION(KILL, DENY) = KILL`. Both attempts are recorded; neither takes
effect. ✔

**Example 5 — a boolean permission cannot be enabled downstream.**

```
Baseline: allow_persistence: false   (the Watcher baseline declares the mandatory set)
Project:  allow_persistence: true
```
`AND(false, true) = false`. ✔ Because the *baseline* declares the forbid, no
downstream layer can lift it. The documented, single escape hatch is editing the
baseline — a top-level deployment decision, which is where such an authority belongs.

### 5.4 Evaluation order for a resolved policy

Deterministic and fixed (this is the ordering that makes "DENY > ALLOW" and "KILL
tripwire > ordinary rules" true by construction):

1. Session killed? → `KILL` (unchanged, `watcher/watcher.py:343-360`).
2. Tripwires (any layer's) → the merged tripwire decision (`KILL` unless a layer
   escalated it, which is impossible by `MAX_DECISION` monotonicity).
3. Rate limits (§6) — before policy, because a rate-limit hit is a fact about
   admission, not about the action's semantics, and must not be masked by a rule that
   would have allowed it.
4. `deny` union (filesystem, network, tools).
5. `allow` intersection (only if at least one layer declared one).
6. Boolean permissions and host-boundary rules.
7. Process and runtime ceilings.
8. Default: the baseline's `default` decision. V3's default is `ALLOW` when nothing
   matches (`policy.py:185-190`); the V4 baseline keeps that for V3 compatibility but
   the resolved policy records `default_decision` explicitly so it is a declared value
   rather than an accident.

### 5.5 Conflict kinds

| Kind | Severity | Resolution |
|---|---|---|
| `CEILING_RAISED` | RECORDED | clamped to the stricter value |
| `MODE_RELAXED` | RECORDED | lattice-min wins |
| `MANDATORY_RULE_WEAKENING` | **REFUSED** | the stronger rule stands; the layer is refused at load time if it explicitly *removes* a mandatory rule |
| `ALLOW_SET_WIDENED` | RECORDED | intersection wins |
| `CONTRADICTION` | RECORDED | same layer allows and denies the same pattern → deny wins |
| `EMPTY_ALLOW_SET` | **WARNING (loud)** | intersection is empty; the policy permits nothing. Not an error (fail-closed), but it must be reported: an empty allow-set is far more often a layering mistake than an intent |
| `REDUNDANT_OVERRIDE` | INFO | a lower layer restates a value already implied |

`REFUSED` conflicts make resolution fail with a non-zero exit and a message. Everything
else resolves deterministically **and is recorded**, so the audit shows that a
weakening was attempted even when it did not succeed.

### 5.6 Provenance

`ResolvedPolicy` records, for every effective field, **which layer set it**: a
`Provenance{field, level, layer_name, value, digest}` list. This is what lets
`watcher policy resolve --explain` answer "why is `/etc/**` denied?" with "organization
policy `acme-base` line 12". Provenance is canonicalized (sorted by field path) before
digesting, so it cannot introduce order dependence.

---

## 6. Rate-limit model

### 6.1 Design constraints from the mission

Deterministic (no probabilistic decisions); same normalized event sequence + same
policy + same state → identical result; a supervisor-owned clock and state; exact
boundary behaviour; a `RATE_LIMIT_HIT` record in the PoE containing counter, window,
limit, observed, action and decision.

A token bucket with fractional refill is **rejected**: it uses floating-point
accumulation driven by clock jitter, so two runs with the same event sequence but
different scheduling produce different refill states. That fails the mission's
determinism requirement outright.

### 6.2 Counters

Closed vocabulary of action classes and their canonical counter ids:

| Counter id | Triggered by |
|---|---|
| `total_actions` | every admitted request, unconditionally |
| `tool_calls` | `tool_request`, `model_call` |
| `shell_executions` | `shell_command` |
| `network_requests` | `network_request`, `api_request` |
| `file_reads` | `file_access` with a read-like action |
| `file_writes` | `file_modification` |
| `subprocess_creations` | `process_creation` |

Classification is a **total** pure function from the normalized request to a set of
counters: every request increments `total_actions` plus at most one class counter; an
action that fits no class increments only `total_actions`. The classification table
carries an `engine_version` recorded in the PoE, so a future reclassification cannot
silently change the meaning of an old trace.

### 6.3 Windows and exact boundary behaviour

Scope window lengths: `per_second = 1s`, `per_minute = 60s`, `per_session = ∞`.

A window is identified by an integer index from the supervisor's authoritative clock:

```
window_index(scope, t) = floor(t / window_seconds(scope))       # t = supervisor clock
```

Semantics, stated exactly:

- The counter is incremented **before** the comparison, so `observed` includes the
  current attempt.
- **Allowed** iff `observed <= limit`.
- Therefore with `limit = 100` per minute: attempts 1..100 are `ALLOW`, attempt 101 has
  `observed = 101 > 100` and is a deterministic violation. This is the brief's example,
  exactly.
- `limit = 0` means "this class is forbidden": attempt 1 has `observed = 1 > 0` and is
  the violation. This is a useful, deterministic way to express a hard prohibition.
- A counter that the resolved policy does not declare is unbounded.
- `per_session` counts from session start; the window index is `0` for the whole
  session.

**Window-boundary semantics (fixed window).** Two attempts can be admitted
back-to-back across a window boundary and be counted in different windows, so the true
worst case is up to `2 × limit` in a sliding 1-second/1-minute window. This is a
**documented, bounded** imprecision, chosen because it is exactly reproducible.
`ResolvedPolicy` records the windowing mode, so the imprecision is a declared property
of the policy rather than a hidden one.

**Deterministic sliding window (optional, Phase 3b).** A ring of the last
`window_seconds / resolution` counter buckets keyed by window index gives the exact
sliding count with no floats and no probabilistic state. This is also fully
deterministic, and is preferred when the operator wants no boundary burst. The mode is
part of the policy and part of the digest, so switching modes changes the
`resolved_policy_digest` and is visible.

### 6.4 Where time enters, and why that is still deterministic

The mission's invariant is:

```
same normalized request + same resolved policy + same authoritative Watcher state
    = same security decision
```

Wall-clock time is *environment*, and the invariant explicitly excludes it from the
deterministic inputs. The design makes this honest rather than hand-waved:

- The supervisor reads its authoritative clock **once per admitted request**, at a
  defined point inside the same critical section that decides and records.
- The resulting `window_index` **is recorded in the PoE** as part of the
  `RATE_LIMIT_HIT` (and, for the counters consulted, as part of the decision event).
- Therefore a trace can be *replayed* by feeding the recorded window indices back in,
  and replay reproduces every decision bit-for-bit. Determinism is achieved by making
  time a recorded part of the state, not by pretending the clock is deterministic.
- A verified-consistent clock is not possible in the general case; the design does not
  claim it. What it claims is: **given the same recorded state, the same decision**.

The test that enforces this is a replay test: run a scripted sequence through the
limiter with an injected clock, record every `window_index`, then replay the recorded
state and assert an identical decision sequence (§13).

### 6.5 The `RATE_LIMIT_HIT` record

A new `EventType.RATE_LIMIT_HIT` (safe: `tests/test_v2_boundaries.py:374-396` pins the
event payload *keys*, not the enum's membership), with:

```
action:     the request's action
resource:   the request's resource
decision:   the configured on_violation action for `rate_limit`
risk:       HIGH
reason:     "rate limit exceeded: shell_commands.per_minute 31 > 30"
metadata:
  counter:        "shell_commands.per_minute"
  window_index:   29184021
  window_seconds: 60
  window_start:   1751328000          # authoritative, derived from the index
  limit:          30
  observed:       31
  scope:          "per_minute"
  action_class:   "shell_executions"
  on_violation:   "QUARANTINE"
  decision:       "QUARANTINE"
  resolved_policy_digest: "..."
```

Plus a second event type `RATE_LIMIT_STATE` optionally appended at session end with the
final per-counter totals, so a reader does not have to fold the whole trace to know the
budget consumed.

### 6.6 Implementation placement and race freedom

- **Admission** for every request continues to pass through the existing single choke
  point `IpcServer._begin_write` (`ipc/server.py:645-657`). A limiter refusal there
  needs a new, distinct `ErrorCode` (today only `NOT_READY` and
  `TOO_MANY_CONNECTIONS` exist, `protocol.py:107-109`).
- **Accounting** lives in the supervisor, at `_handle_evaluate`/`_handle_event`, inside
  `self._lock` — which `_handle_evaluate` already holds across the whole evaluation
  (`daemon.py:1191-1209`). Because the counter increment, the comparison, the decision
  and the record are in one critical section, concurrent requests cannot interleave a
  read-modify-write. This is the property the concurrent-accounting test asserts.
- **Trace amplification** (R-14) is bounded by `total_actions.per_session` plus a
  **byte budget** on the in-memory trace. The byte budget is not a policy rule (it is a
  supervisor self-protection limit) and its exhaustion is recorded as a supervisor
  event, not a policy denial.
- **No `sleep()` as synchronization** anywhere in the limiter. Waiting is not part of
  the model: a rate-limited action is *refused*, never *delayed*. Delaying would make
  scheduling part of the decision, which is precisely what must not happen.

---

## 7. Public Integration API V1

### 7.1 Naming — resolving the `Decision` collision (ODD-1)

The mission asks for a public `Decision` object exposing `decision, rule_id, reason,
risk, policy_digest, session_id`. But `the_watcher.Decision` is **already** the public
verdict enum (`watcher/decision.py:12-18`, exported at `__init__.py:125`), and V1/V2/V3
compatibility forbids changing it.

**Proposed resolution:** the Integration API is a new namespace, and the result object
is `Decision` *within that namespace*:

```python
from the_watcher.api import (
    ActionRequest, Decision, DecisionReason, SessionInfo, PolicyInfo,
)
```

- `the_watcher.Decision` — unchanged enum (`ALLOW|DENY|QUARANTINE|KILL`).
- `the_watcher.api.Decision` — the result record, whose `.decision` field is the enum.

No existing import changes meaning; `from the_watcher import Decision` still yields the
enum. The alternative (renaming the enum) breaks V1/V2/V3 and is rejected. The
alternative (naming the result `DecisionResult`) diverges from the brief's vocabulary;
it is the fallback if the namespaced overlap is judged too subtle. Flagged as ODD-1.

### 7.2 Objects

```python
@dataclass(frozen=True)
class ActionRequest:
    action: str                      # required; mapped to an event type
    resource: str = ""
    metadata: Mapping[str, Any] = {} # UNTRUSTED client context
    request_id: str | None = None    # optional idempotency/replay token

@dataclass(frozen=True)
class DecisionReason:
    code: str                        # closed vocabulary, e.g. "forbidden_path"
    detail: str                      # human sentence
    rule_id: str                     # stable rule identifier
    tripwire_id: str | None = None
    counter: str | None = None       # rate-limit fields, when applicable
    limit: int | None = None
    observed: int | None = None
    window_index: int | None = None
    def __str__(self) -> str: ...    # back-compatible rendering

@dataclass(frozen=True)
class Decision:
    decision: DecisionVerdict        # the enum
    rule_id: str
    reason: DecisionReason | str
    risk: Risk
    policy_digest: str               # resolved_policy_digest
    session_id: str
    # authoritative extras, each explicitly supervisor-owned:
    sequence: int
    decided_at: int                  # authoritative unix seconds
    limits: Mapping[str, int] | None # remaining budget, when known

@dataclass(frozen=True)
class PolicyInfo:
    version: int
    resolved_policy_digest: str
    layers: tuple[LayerInfo, ...]
    conflicts: tuple[PolicyConflict, ...]
    hard_limits: Mapping[str, int]

@dataclass(frozen=True)
class SessionInfo:
    session_id: str
    state: str
    killed: bool
    quarantined: bool
    event_count: int
    head_hash: str
    final_hash: str | None
    policy_digest: str
    started_at: int
```

`Decision` must **never** expose a private internal object. A test asserts that every
public dataclass field is a primitive, an enum, a tuple of those, or another public
dataclass — and that no field type comes from `ipc.*`, `supervisor.*` or
`enforcement.*`. That single test is what enforces the mission's "no private internal
objects should leak into the public API".

### 7.3 Exposing on the wire, without leaking internals

Reusable as-is: the EVALUATE payload shape (`daemon.py:1187-1198`),
`_decision_payload` (`1391-1399`), `Evaluation`'s `reason`/`rule`/`tripwire_id`
(`decision.py:60-113`).

Must **not** be exposed (audit §8 of the IPC review), each of which is currently one
attribute access away inside the daemon:
`daemon.policy` (a live **mutable** `Policy`, `daemon.py:318-320` + `policy.py:87` —
disclosing the rule set *and* permitting silent reconfiguration);
`daemon.trace`/`daemon.watcher` (the full PoE including other clients' metadata);
`daemon.paths`/`storage.root` (the authoritative trace location the workload must not
be able to target); `daemon.process`/`command` (the workload's command line);
`daemon.enforcer`/`unit`/`evidence` (namespace paths, host pids); and `stats()`
(`daemon.py:1805-1818`), which returns the entire metadata dict including
`policy.to_dict()`, `tripwires`, `ipc.limits` and `verification`.

Design: a public API adapter layer translates internal state into the five public
dataclasses with an explicit field allow-list, mirroring the existing
`_SAFE_CLIENT_FIELDS` discipline in the handshake (`server.py:86-104`) — which is done
correctly and should be the pattern for the rest of the surface.

**`PolicyInfo` is operator-side only.** Disclosing forbidden paths and allowed domains
to the untrusted workload is evasion material. The client-visible variant carries only
`version` and `resolved_policy_digest`, which is enough for a workload to detect a
policy change without learning the rules.

### 7.4 Zero-code mode stays primary — and what that honestly means

`watcher run --enforced -- python agent.py` must keep working with **no import of
Watcher in `agent.py`**. Enforcement must never depend on the SDK. That property exists
today and must not regress. A test asserts the CLI path contains no SDK dependency.

But V4 must be precise about what zero-code mode enforces, because R-2 makes this easy
to overstate. With **no SDK instrumentation**:

| Enforced by the kernel | Mechanism |
|---|---|
| Filesystem allow-list (read/write/execute) | Landlock allow-list, applied in the guard (`exec_guard.py:326-334`) |
| All network egress | empty network namespace (`namespaces.py:666-667`) or the §8 design |
| Namespace/mount/ptrace/bpf/module/reboot syscalls | seccomp denylist, `EPERM` (`seccomp_filter.py:275-303`) |
| Privilege escalation | all capabilities dropped + `no_new_privs` (`exec_guard.py:174-213`) |
| Memory/CPU/process/file-size ceilings | rlimits, plus cgroups where delegated (§9) |
| Process-tree containment and kill | PID namespace + `terminate_tree` |

**Not enforced without instrumentation:**
- Any *semantic* policy rule — `tool_calls`, named-domain rules, protected environment
  variables, persistence and privilege-escalation regexes on command lines. Nothing
  reports those events; the policy engine is only consulted when the workload (or a
  host monitor) asks (`watcher/watcher.py:325`).
- PoE richness. The trace records lifecycle and containment events, not the workload's
  actions.

V4 must state this in `docs/containment.md` and in the README, and must not present
"policy" and "enforcement" as the same thing. Closing the gap (syscall-level
observation via `SECCOMP_RET_USER_NOTIF`, `fanotify`, or eBPF) is explicitly **out of
scope** for V4 Phase 1 and is listed as a research item in §15.

### 7.5 Python SDK

```python
from the_watcher import WatcherClient

client = WatcherClient.from_environment()

decision = client.evaluate(
    action="tool_call",
    resource="shell",
    metadata={"command": "..."},
)

if not decision.allowed:
    raise RuntimeError(f"denied by {decision.rule_id}: {decision.reason}")
```

SDK obligations, each with an enforcing test:

| Obligation | How |
|---|---|
| Use the existing authenticated IPC | reuse `ipc/client.py` and its handshake; no new transport |
| Fail closed by default | keep `fail_mode=fail_closed` (`client.py:338-354`); a test asserts a dead supervisor yields `DENY`, and that `fail_open` is *not* reachable from `from_environment()` without an explicit argument |
| Never decide policy locally | the SDK contains no rule evaluation; a test asserts the module imports nothing from `watcher.policy` |
| Never own authoritative timestamps | no timestamp is sent or trusted; a test asserts the frame contains no authoritative field |
| Never own sequence numbers | as above (`protocol.py:115-125`) |
| Never own the PoE | the SDK has no trace, recorder or chain access |
| Treat all client fields as untrusted | reuse `strip_authoritative_fields` (`protocol.py:402-424`) |

`WatcherClient.from_environment()` reads the existing child-environment connection
variables (`daemon.py:895-906`) and validates them; it must not accept
configuration that changes security posture implicitly. The existing `from_environment(**overrides)`
escape hatch (`client.py:180-219`) is retained for tests but must not be the
documented path.

---

## 8. Network enforcement design options

This section is the **pre-implementation engineering decision document** the mission
requires. No implementation is proposed for Phase 1 beyond what the decision supports.

### 8.1 What exists today

Two postures only: `network=none` creates a fresh network namespace via `unshare
--net`, containing only `lo` **down** and no routes, so egress fails with `ENETUNREACH`
(`namespaces.py:666-667`, verified at `test_v3_containment.py:405-412`); `network=open`
creates **no** network namespace at all, so the sandbox shares the host stack. Nothing
brings `lo` up — there is no `SIOCSIFFLAGS`/`ip link` call anywhere.

`network=restricted` is refused twice, honestly and with a reason:
`namespaces.py:168-176` ("needs host network privileges to program an egress
allow-list, which the rootless namespace backend does not have") and
`docker.py:87-91`. `ContainmentProfile.validate` already guarantees a non-empty
`allowed_networks` when the mode is `restricted` (`profile.py:403-407`).

A self-inflicted inconsistency also exists: for `open`, `inspect()` appends
"network=open: the sandbox shares the host network namespace, so egress is not
restricted" (`namespaces.py:819-823`), which sets `verified=False`, which makes
`_serve_enforced` raise and destroy the unit (`daemon.py:740-760`). **So any
`network != none` profile — including `--network open` and the `dev` preset — can never
complete an enforced session.** That is a bug to fix regardless of the egress decision.

### 8.2 Options evaluated

| # | Option | Rootless? | Real OS enforcement? | Direct-socket bypass? | Verdict |
|---|---|---|---|---|---|
| A | nftables/iptables inside a netns | Yes (CAP_NET_ADMIN *inside* the namespace) | Yes, but | — | **Useless alone**: the netns has no uplink, so there is nothing to filter. Filtering real egress needs a veth pair with one end in the host netns, which needs host privilege. |
| B | nftables/iptables in the host netns | **No** — needs real CAP_NET_ADMIN | Yes | Blocked | Viable only with root. Offer as an explicit, privileged, opt-in backend that the operator must request; never silently require root. |
| C | Empty netns + userspace proxy over an AF_UNIX socket | **Yes** | **Deny-all is kernel-enforced**; the allow-listed path is cooperative | **Blocked by the kernel** | **Recommended.** Direct sockets cannot leave: no routes, no DNS. The only path out is the proxy. |
| D | Proxy only (HTTP_PROXY env, no netns) | Yes | **No** | Trivially bypassed | **Rejected.** This is exactly the "user-space advisory-only rule presented as OS enforcement" the mission forbids. |
| E | `BPF_CGROUP_INET_EGRESS` socket-address filter | Only with unprivileged BPF enabled *and* a delegated cgroup subtree | Yes | Blocked | Research item. Probe at runtime; report in `doctor`; never assume. |
| F | Landlock network rules (ABI 4+) | Yes | Yes, but | — | **Rejected**: Landlock's net rights are **port-based** (`BIND_TCP`/`CONNECT_TCP`) and cannot express an address or domain allow-list. Only `handled_access_fs` is currently set (`landlock_ruleset.py:106-107`). |
| G | DNS-only filtering / a stub resolver returning NXDOMAIN | Yes | **No** | Bypassed by any hardcoded IP or by using an IP literal | **Rejected.** The mission explicitly forbids "fake DNS-only protection". |

### 8.3 Decision

**Phase 1 (recommended): implement option C, and only option C.**

- The workload runs in a **new network namespace with no uplink** (today's `none`
  posture), so the kernel denies every direct outbound connection — this is the
  fail-closed foundation and it is already proven to work
  (`test_v3_containment.py:405-412`).
- A **supervisor-owned egress broker** is reachable over the AF_UNIX socket in the
  already-mounted control directory (the mechanism exists: `control_inner` bind at
  `namespaces.py:584-592`, endpoint env at `daemon.py:647-675`). AF_UNIX needs no
  network namespace, so an empty netns is not an obstacle.
- The broker enforces the policy's domain allow-list **after** resolution, and
  **pins the resolved address** for the connection, so a DNS answer cannot be swapped
  between the check and the connect (DNS-rebinding/TOCTOU). It denies redirects to
  non-allow-listed hosts, denies non-`http(s)` protocols, and denies IP-literal
  targets unless the policy explicitly allows an address.
- **Fail-closed:** if the broker is not running or exits, egress is impossible — the
  broker is the only route out. Its lifecycle is tied to the containment unit and
  hooked into the existing `Enforcer.isolate_network` teardown hook
  (`base.py:330-332`, called from `daemon.py:807-820`).

**What V4 may and may not claim for option C.** It may claim: *"direct network access
is denied by the kernel; outbound access is available only through a supervisor-owned,
allow-listed broker."* It may **not** claim transparent interception: the workload must
be configured to use the broker (proxy environment variables / a broker-aware client).
A workload that needs raw sockets to an allow-listed IP is **not supported** by this
design, and V4 must refuse that request explicitly rather than pretend. This is the
honest boundary, and it is why option C is a *capability* restriction rather than a
transparent one.

**Option B** is offered additionally, behind an explicit
`--enforcement-backend nftables` (never default, never implied), only when `doctor`
proves real host privilege. It must never be reached by `auto`.

**Phase 1 keeps the refusals in place until option C is implemented and tested.** V4
ships no partial claim: `network=restricted` continues to be refused with the existing
clear message until the broker path is complete. Section 15 records that a V4 release
which does not complete option C still refuses `restricted` — and that this is the
correct outcome, not a shortfall to paper over.

**Not Phase 1 work.** The `network=open` self-refusal described in §8.1 and
`is_reduced_protection` honesty (`profile.py:452-453`) for postures weaker than
`none` are V3-side concerns belonging to the V3 hardening set (§19); Phase 0
already touched `profile.py` for the declared-versus-enforced work. Phase 1 is
the Policy V1 document format and touches no V3 runtime file: it **changes no V3
behaviour**, and it is **not runtime-wired**.

### 8.4 Required `doctor` reporting

`doctor` must report egress enforcement as one of `AVAILABLE` / `PARTIAL` /
`UNAVAILABLE`, with the specific mechanism, and must distinguish "kernel-denied
deny-all" from "allow-listed broker path" from "no enforcement". It must never report
a mode as enforceable unless a real probe succeeded.

---

## 9. cgroup design

### 9.1 What exists

Probing only. `_probe_cgroups` (`capabilities.py:312-323`) checks
`/sys/fs/cgroup/cgroup.controllers` (else `/proc/cgroups`) and reports a version and a
controller list used solely by `doctor_report` (`214-220`). `EnforcementEvidence.cgroup`
holds a read-only path string from `procfs.read_cgroup` (`base.py:99`,
`namespaces.py:853`, `docker.py:280`). **No code writes `pids.max`, `memory.max` or
`cpu.max`; there is no cgroup namespace request, no delegation check, no teardown.**

rlimits do work and must keep working: `RLIMIT_NPROC` (per-uid baseline + budget),
`RLIMIT_NOFILE`, `RLIMIT_STACK`, `RLIMIT_AS` from `memory_mb`, `RLIMIT_FSIZE`,
`RLIMIT_CORE`, `RLIMIT_CPU` (`resource_limits.py:71-119`, applied at
`exec_guard.py:318-324`).

### 9.2 What cgroups buy

| Limit | Today (rlimit) | cgroup v2 |
|---|---|---|
| memory | `RLIMIT_AS` — **address space**, over-counts; a process can be killed for mapping, not using, memory (`resource_limits.py:19-22`) | `memory.max` — **RSS**, the semantics the policy intends |
| pids | `RLIMIT_NPROC` — **per-UID and host-wide**, so it must be biased by a measured baseline (`resource_limits.py:6-18, 80-86`) | `pids.max` — exact, per-unit |
| CPU rate | **not enforced at all** (R-7: `resources.cpus` reaches only Docker) | `cpu.max` — real quota |
| CPU time | `RLIMIT_CPU` from `max_runtime_seconds` | `cpu.stat usage_usec` — accurate accounting |
| emptiness | namespace inode (R-6, unsound) | `cgroup.events populated=0` — an **independent** proof |

### 9.3 Design

**Probe, do not assume.** `_probe_cgroups` is extended to prove *delegation* by
actually creating a child cgroup, writing `pids.max` and `memory.max`, reading them
back, and removing it. Only then is the capability reported. New fields
`cgroup_v2_writable`, `cgroup_delegation_detail`, and per-resource status
(`membership/state`) go into `HostCapabilities` (`capabilities.py:74-107`), `to_dict`
(`137-164`) and `doctor_report` (`168-243`). The module's existing rule — every probe
is a real check (`capabilities.py:7-9`) — is honoured.

**Split creation from verification, because rootless constraints require it.** Writing
to the host cgroup hierarchy from inside a rootless user namespace normally requires a
pre-delegated subtree, so:

- **Supervisor side:** create the per-unit cgroup, set `pids.max`/`memory.max`/`cpu.max`,
  and attach the workload before it is confined. Add a cgroup path to `SandboxSpec`
  (`base.py:183-223`) so it reaches the guard payload (`namespaces.py:623-646`), and
  record it on `ContainmentUnit.metadata` (`namespaces.py:350-360`).
- **Guard side (inside the sandbox):** a new `enforcement/linux/cgroup_limits.py`
  honouring the existing guard contract — **stdlib-only, no intra-package imports**,
  which is enforced AST-wise by `test_v3_capabilities.py:221-279`. Register it in
  `GUARD_MODULES` (`namespaces.py:67-72`) so `_install_guard` (`418-445`) copies it.
  Call it from `exec_guard.main` **between step 1 (mounts, `312-317`) and step 3
  (Landlock, `326-334`)** — i.e. before the capability drop at step 5, since writing
  cgroup files may need the capability — and emit `report["cgroup"]` in the same
  `{"applied": {...}, "problems": [...]}` shape as `resource_limits.apply_limits`
  (`resource_limits.py:119`).

**Additive, never a replacement.** rlimits continue to be applied everywhere, because
they work on every platform and need no delegation. cgroups are applied **only** where
the probe proved they are available and writable. The resolved resource ceiling is the
**stricter** of the rlimit and the cgroup value (`MIN`, consistent with §5.2).

**Independently sound emptiness proof.** `verify_empty` (`namespaces.py:1042-1044`)
gains the cgroup check where available: `cgroup.events populated=0` is a proof that
does not depend on a namespace inode, closing R-6's soundness gap. Where cgroups are
unavailable, the namespace-inode check is **strengthened** rather than left as-is: key
on the **PID namespace** (unforgeable for a process that stays in it), or the union of
user+pid, and treat an unreadable namespace as "not empty". Also fix the
`unit.namespaces = {}` overwrite bug at `namespaces.py:762` (only replace when
non-empty), which currently produces spurious `KILL_FAILED` events. Add `clone` to the
seccomp deny tables so the specific escape R-6 describes is blocked as well as
detected.

**Teardown.** Remove the cgroup in `terminate` (`namespaces.py:925-1030`) after
confirming emptiness. Report the outcome in `TerminationOutcome` (`base.py:145-175`).

### 9.4 `doctor` reporting contract

Per resource — memory, pids, CPU — and per mechanism — rlimit, cgroup — `doctor`
reports exactly one of:

- **`AVAILABLE`** — the probe created a cgroup and the write succeeded.
- **`PARTIAL`** — cgroups exist and are readable but the unit cannot be delegated (e.g.
  no `cgroup.subtree_control` delegation to this user); rlimits still apply, and the
  report says which limits are therefore approximated rather than exact.
- **`UNAVAILABLE`** — no cgroup v2, or writes refused.

**Never claim cgroup enforcement when unavailable.** A test asserts that on a host
where the probe fails, no trace event claims cgroup enforcement and `doctor` says
`UNAVAILABLE`. This mirrors the existing honesty test at
`test_v3_capabilities.py:62, 73`.

---

## 10. PoE anchoring design

### 10.1 The gap being closed

`verifier.py:160-164` is a self-consistency check over data read from the same file,
and `declared_final_hash` is itself read from that file (`trace.py:304-306`). An
attacker with write access to the trace storage rewrites events, calls `relink(0)`
(`trace.py:199-221`), re-seals (`trace.py:194-197`), and passes verification. The code
and README state this honestly (`trace.py:199-207`, `README.md:232-235`); V4 makes it
detectable.

### 10.2 Interface

```python
class Anchor(Protocol):
    name: str
    def anchor(
        self,
        *,
        session_id: str,
        schema_version: str,
        event_count: int,
        final_hash: str,
        timestamp: int,
        policy_digest: str,
    ) -> AnchorReceipt: ...

@dataclass(frozen=True)
class AnchorReceipt:
    backend: str
    anchored_hash: str          # the value committed
    anchored_at: int            # the anchor's own timestamp
    external_ref: str           # path, URL, or receipt id
    sequence: int               # position in the anchor log
    previous_anchor_hash: str   # chains the anchor log itself
    proof: Mapping[str, Any]    # backend-specific, e.g. HTTP status
```

The anchored value is a **composite**, not the bare final hash:

```
anchored_value = sha256_hex(canonical_bytes({
    "schema_version": schema_version,
    "session_id": session_id,
    "event_count": event_count,
    "final_hash": final_hash,
    "policy_digest": policy_digest,
}))
```

Including `session_id` prevents replaying another session's anchored hash; including
`policy_digest` binds the anchored evidence to the policy that was in force (§4.7);
including `event_count` binds the length.

### 10.3 Backends

1. **`FileAnchor`** — an append-only anchor log at a path **outside** the trace storage
   root, default `$WATCHER_HOME/anchors/anchor.log`, one canonical-JSON line per entry,
   opened `O_APPEND`, `fsync`ed per entry via the existing `_atomic_write` discipline
   (`storage.py:78-102`) plus the currently-missing parent-directory fsync. Entries are
   **chained**: each carries `previous_anchor_hash`, so truncation or deletion of a
   middle entry is detectable, not just a rewrite of the tail.
2. **`HttpAnchor`** — a generic webhook: `POST` the canonical JSON body to a
   configured URL, requiring a `2xx` and storing the response digest as `proof`.
   Timeout-bounded, fail-closed, no retries that could reorder entries. **Generic
   interface only** — no vendor SDK, no credentials in policy, no dependency.
3. **`NullAnchor`** — the default. Anchoring is **optional**; absent configuration
   means no anchor and the verifier reports `anchor_status = "not_requested"`.

A pluggable adapter registry mirrors `select_backend` (`enforcement/base.py:365-411`)
so a user can add a backend without touching core.

**Explicitly not doing:** no blockchain, no ledger, no signatures, no identity. The
project's independence statement (`__init__.py:29-30`, tested at
`test_v2_boundaries.py`) forbids it, and a signature needs an identity to be
meaningful.

### 10.4 Verifier changes

**Separate, additive verdicts.** `VerificationResult` keeps `verdict`/`valid` exactly
as they are (existing tests and the CLI depend on them) and gains:

```
trace_valid: bool            # today's self-consistency statement, renamed in meaning only
anchor_status: str           # "not_requested" | "valid" | "missing" | "mismatch" | "unreachable"
anchor_valid: bool | None    # None when not requested or not checkable
anchor_ref: str | None
anchored_hash: str | None
```

New `TamperSignal` members: `ANCHOR_MISSING`, `ANCHOR_MISMATCH`, `ANCHOR_UNREACHABLE`,
`ANCHOR_TRUNCATED`. New CLI surface:

```
$ watcher verify trace.json --anchor ~/.local/state/the-watcher/anchors/anchor.log
TRACE VALID     (1284 events, final=9f3c1a...)
ANCHOR VALID    (file, entry #37, anchored 2026-04-02T11:03:22Z)

$ watcher verify tampered.json --anchor ...
TRACE VALID     (1284 events, final=9f3c1a...)
ANCHOR MISMATCH the anchor records b41d9e... for this session at 1284 events
```

Exit `0` only when both hold; exit `1` with the specific failure otherwise. The two
lines must stay separate — collapsing them would hide exactly the gap that makes the
anchor worth having.

**Also fixed here (R-4/R-5):**
- A **sealed** trace whose JSON lacks `final_hash` is `invalid`, not `valid`.
- An empty trace is `invalid` in both `verify` and `verify_dict` (today
  `verify_dict` rejects and `verify` does not, `verifier.py:187-194`).
- `verify_file` catches `ValueError`/`TypeError` too, so a malformed `created_at`
  (`trace.py:302`) yields `invalid` rather than a traceback (R-24).
- The `TRACE_SEALED` off-by-one: `daemon.py:1641` records `event_count` **before**
  appending that event; it must record the post-append count.
- Anchor commit happens **after** `seal()` and **after** `_verify_sealed()`, between
  `daemon.py:1646` and the storage writes at `1651-1652`, so an unsealed or
  non-verifying trace is never anchored.

### 10.5 Residual risk, stated plainly

`FileAnchor` protects against rewriting `trace.json`; it does **not** protect against
an attacker who owns the entire state directory (they can rewrite the anchor log, and
the anchor-log chain only makes truncation detectable, not forgery). Only an anchor
outside the attacker's reach — `HttpAnchor` to a system the operator controls — raises
the bar. V4 documents this and does not claim more. The verifier output distinguishes
`TRACE VALID` from `ANCHOR VALID` precisely so a reader can see which property they
actually have.

---

## 11. Migration and backward compatibility

### 11.1 Frozen surfaces

| Surface | Guarantee | Enforced by |
|---|---|---|
| `the_watcher` public `__all__` (61 names) | additive only; no renames, no removals | `tests/test_packaging.py`, V1 tests |
| `Decision`, `Risk` enum members | frozen | `tests/test_watcher.py`, `test_v2_boundaries.py` |
| Event payload key set (11 keys) | frozen | `tests/test_v2_boundaries.py:374-396` (C-1) |
| `schema_version == "watcher-poe/1"` | frozen | same test |
| CLI subcommands `run status verify demo doctor` | kept; new `policy` group is additive | `tests/test_packaging.py:174-187` (C-2) |
| CLI flags, defaults, exit codes | frozen | §3.3 C-4 |
| `watcher run --enforced -- <cmd>` with no SDK import | frozen | new regression test |
| Zero runtime dependencies | frozen | `pyproject.toml:20-21`, `tests/test_packaging.py:28-66` (C-3) |
| V3 `ContainmentProfile` JSON shape | frozen; new fields optional | `tests/test_v3_profile.py` |
| `TamperSignal` existing members | frozen; new members additive | `tests/test_tampering.py` |

### 11.2 Adding things without breaking the freeze

The event payload freeze (C-1) is the binding constraint. Consequences:

- `policy_digest` and `resolved_policy_digest` go in the hashed **`metadata`**, not as
  event fields (§4.7). `metadata` is already part of `hashed_payload()`
  (`poe/event.py:182-193`), so the digests are already chain-covered and anchor-covered.
- New `EventType` members (`RATE_LIMIT_HIT`, `POLICY_RESOLVED`, `RATE_LIMIT_STATE`,
  `ANCHOR_WRITTEN`, `ANCHOR_FAILED`) are additive; the freeze is on the payload keys,
  not the enum. `EVENT_TYPES` grows, and `coerce_event_type` already accepts unknown
  strings (`poe/event.py:100-110`).
- No change to `hashed_payload()` ordering, key set or encoding. A change there would
  invalidate every existing trace and is out of scope.

### 11.3 Legacy policies and the Windows normalization change

`watcher run --policy FILE` dispatches **deterministically** on the document:

- Document contains `version` → parse as Policy V1.
- Document contains none of the V1 keys and matches the legacy shape → parse as the V3
  `Policy` (`policy.py:491-548`), unchanged.
- A document with a mix of both shapes, or an unknown `version` → **error** with both
  interpretations named. No guessing.

`--policy-format {auto,v1,legacy}` exists to remove even that inference for scripted
use.

**The one real behaviour change:** Policy V1 stops case-folding paths on Windows
(§4.4), because platform-dependent normalization violates the cross-platform
determinism invariant. Containment:

- Legacy V3 `Policy` documents keep **exactly** today's behaviour, including
  `normalise_path`'s Windows lowering (`matching.py:52-53`). Nothing in V1/V2/V3
  changes.
- Policy V1 documents get the platform-independent semantics and must declare
  `case_sensitive` explicitly (or accept `auto`, whose resolved value is recorded in
  the digest).
- A migration note and a `watcher policy validate --explain-platform` diff show the
  operator exactly which rules change behaviour on their platform before they switch.

### 11.4 CLI additions

```
watcher policy validate FILE [--json]              # exit 2 on any issue, all issues reported
watcher policy resolve  FILE [FILE...] [--json] [--explain]
watcher policy digest   FILE [FILE...]             # prints both digests
watcher run --policy FILE [--policy-format auto|v1|legacy] ...
watcher run --anchor file:PATH | http:URL          # optional
watcher verify TRACE [--anchor REF]
watcher doctor [--json] [--containment-profile NAME|FILE] [--workspace DIR] [--egress] [--cgroups]
```

All additive. `tests/test_packaging.py:174-187`'s regex should be widened in the same
change to include `policy`, so the guard actually covers the new surface (C-2).

### 11.5 Version and packaging

`__version__` → `0.4.0` in both `pyproject.toml:7` and `__init__.py:101` (they are kept
in step by `tests/test_packaging.py:28-66`). `SCHEMA_VERSION` stays `watcher-poe/1`.
A new `policy_schema_version = 1` and `engine_version` are introduced for the policy
and rate-limit layers (§6.2).

---

## 12. Implementation phases

Each phase is independently reviewable and independently revertible, and no phase
starts until the previous one is green on the full suite.

| Phase | Deliverable | Touches | Risk |
|---|---|---|---|
| **0. Decisions** | This document reviewed; `docs/network-egress-decision.md` finalised; the eight internal docs stubbed with honest status; README claims corrected for R-7/R-25/R-26 | docs only | none |
| **1. Policy V1 model** | `watcher/policy_v1.py`: schema, strict validation, normalization, glob engine, both digests, issue reporting. **Pure library, wired to nothing.** | new module, `matching.py` (glob helpers) | low |
| **2. Layering** | `watcher/layers.py`: `PolicyLevel`, `PolicyLayer`, `PolicyResolver`, `ResolvedPolicy`, `PolicyConflict`, provenance, legacy projection (§4.8) | new module | medium — the merge lattice is the security-critical part |
| **3. Rate limits** | Counter model, fixed (and optional sliding) windows, supervisor-owned accounting at the existing choke point, `RATE_LIMIT_HIT`, trace byte budget | `ipc/server.py` (admission), `supervisor/daemon.py`, `watcher/policy_v1.py` | medium — concurrency |
| **4. Public API + SDK** | `the_watcher/api/` with the five objects; `WatcherClient` public wrapper; leak tests | new package, `ipc/client.py` | medium — surface design is hard to change later |
| **5. Adapter contract** | `the_watcher/adapters/`: `WatcherAdapter.before_action/after_action/on_error`, no framework deps | new package | low |
| **6. Anchor** | `Anchor` protocol, `FileAnchor`, `HttpAnchor`, `NullAnchor`; verifier verdict split; R-4/R-5 fixes | `poe/verifier.py`, `supervisor/daemon.py`, `cli.py` | medium |
| **7. cgroups** | Real delegation probe; `linux/cgroup_limits.py`; `SandboxSpec` cgroup path; `verify_empty` soundness; `doctor` per-resource status | `enforcement/capabilities.py`, `base.py`, `backends/namespaces.py`, `linux/exec_guard.py`, new guard module | medium-high — kernel-facing |
| **8. Network egress** | Option C per §8: broker + empty netns, `isolate_network` integration, `doctor` egress verdict; fix the `network=open` self-refusal | `enforcement/backends/namespaces.py`, `daemon.py`, new broker module | **high** — gated on the decision doc |
| **9. Hardening** | R-1 (orphan finalization + signal handling), R-2 (documented precisely in §7.4), R-3 (peer PID no longer authoritative), R-6, R-8..R-13, R-14, R-15, R-16, R-17, R-19..R-24 | `supervisor/daemon.py`, `ipc/*`, `enforcement/*`, `cli.py` | medium |
| **10. Docs + performance** | The eight `docs/*.md` files finalised; `benchmarks/benchmark_v4.py`; measured numbers per §13.6 | docs, benchmarks | low |

**Sequencing rationale.** Policy V1 is a pure library first (Phase 1) so that the
highest-risk logic — parsing, normalization, globs, digests — is fully tested before
anything depends on it. Layering (Phase 2) is separate because the merge lattice is a
security boundary in its own right. Rate limits (Phase 3) come before the public API
(Phase 4) because the `Decision` object has to carry limit state from the start. The
anchor (Phase 6) is deliberately after the API so that the digest fields it needs are
already defined.

**R-1 is pulled forward.** The orphan-on-abnormal-exit defect is a false audit record
in shipped V3 code. It should be fixed as the **first** code change in V4 — before the
new features — as a standalone, minimal, well-tested patch. Phase 9 lists it because
it belongs to the hardening set, but it must not wait for the hardening phase.

---

## 13. Test plan

### 13.1 Principles

- **No new test dependencies.** Property-style tests use fixed-seed `random.Random`,
  `itertools.permutations` and explicit generators — deterministic and stdlib-only,
  consistent with C-3.
- **Every security invariant in §14 gets a dedicated named test.** The invariant list
  and the test list are the same list.
- **Every new claim in the docs gets a test or an explicit "not implemented" marker.**
  This is the mechanism that prevents V4 from repeating R-7/R-25/R-26.
- **Platform honesty.** A test that cannot run says so with a reason string, following
  `tests/conftest.py:253-283`, and a job that cannot exercise something fails rather
  than silently skipping (the existing pattern at `.github/workflows/ci.yml:156-163`).

### 13.2 New test modules

| Module | Covers |
|---|---|
| `tests/test_policy_v1_schema.py` | parsing, unknown keys at every level, missing required keys, type strictness (no coercion: `"1"`, `1.0`, `"true"`, `"30"`), `on_violation: ALLOW` rejected, `network.allow` with `mode: none` rejected, duplicate spelling of a counter rejected, empty-after-normalization patterns rejected |
| `tests/test_policy_v1_globs.py` | `*`, `**`, `?`, implicit-subtree equivalence, middle-`**`, unsupported syntax rejected with position, **the example-policy witness test** (§4.4 rule 4), case-sensitivity mode, traversal (`..`), symlink-free lexical semantics |
| `tests/test_policy_v1_normalization.py` | list sort+dedupe, A-label IDNA domains, trailing-dot strip, `~`/`$VAR` resolved against the declared base only, undefined var rejected, **platform-independence: the same document normalizes identically on Windows and Linux** |
| `tests/test_policy_v1_digest.py` | digest stability, key-order independence, domain separation (a policy digest is never equal to an event hash for the same bytes), version sensitivity, `name` sensitivity |
| `tests/test_policy_layers.py` | precedence by level not input order, `UNION`/`INTERSECT_UNIVERSE`/`MIN`/`MAX_DECISION`/`LATTICE_MIN`/`AND` semantics, **the five worked examples of §5.3**, duplicate level rejected |
| `tests/test_policy_impossible_weakening.py` | every weakening attempt in the brief: `deny` vs `allow` for `~/.ssh/**`, `restricted`→`open`, ceiling raise, tripwire removal, tripwire downgrade, boolean permission enable, mandatory rule disable — each asserts the *stronger* result **and** a recorded conflict |
| `tests/test_policy_resolver_properties.py` | **permutation invariance**: every permutation of a fixed layer set yields an identical `resolved_policy_digest`; idempotence: resolving twice is stable; associativity across the operator set |
| `tests/test_rate_limits_boundary.py` | `limit=100` → attempts 1..100 `ALLOW`, 101 violation; `limit=0`; `limit=1`; window-index arithmetic at exact boundaries (`t = k·60 - 1`, `t = k·60`, `t = k·60 + 1`); per-session never rolls |
| `tests/test_rate_limits_determinism.py` | **replay test**: record window indices, replay, assert an identical decision sequence; independent of scheduling |
| `tests/test_rate_limits_concurrency.py` | N threads × M requests against a shared limiter: total admitted is exactly the limit, no over-admission, no lost updates, distinct `observed` values |
| `tests/test_rate_limit_poe.py` | the `RATE_LIMIT_HIT` record contains counter, window, limit, observed, action, decision; the event is chain-covered |
| `tests/test_api_objects.py` | **no internal type leaks**: every public field is primitive/enum/tuple/public-dataclass; no field type from `ipc.*`, `supervisor.*`, `enforcement.*`; `the_watcher.Decision` is still the enum; `the_watcher.api.Decision.decision` **is** that enum |
| `tests/test_sdk_contract.py` | no policy evaluation in the SDK (import-graph assertion); no timestamp/sequence/PoE ownership; fail-closed default; `fail_open` not reachable implicitly; forged authoritative fields rejected |
| `tests/test_adapter_contract.py` | adapter lifecycle order, error propagation, no framework imports in core |
| `tests/test_anchor.py` | `FileAnchor` append-only, chained, fsync; truncation of a middle entry detected (`ANCHOR_TRUNCATED`); `HttpAnchor` fail-closed on non-2xx/timeout; `NullAnchor` default; `anchored_value` binds session, count, policy digest; replay of another session's anchor fails |
| `tests/test_verify_anchor.py` | `TRACE VALID` + `ANCHOR VALID` independently; each failure mode's distinct output; exit codes; **the full consistent rewrite of §3.1 R-4 is now caught when an anchor exists and still passes without one** (the honest boundary) |
| `tests/test_cgroup_availability.py` | real-probe semantics; `AVAILABLE`/`PARTIAL`/`UNAVAILABLE`; **no claim of cgroup enforcement when unavailable**; guard module is stdlib-only and import-free (extends `test_v3_capabilities.py:221-279`) |
| `tests/test_network_bypass.py` | with option C: direct socket to an allow-listed host fails (kernel), broker path works, DNS-rebinding pinning, redirect to a non-allow-listed host denied, broker death → egress denied; **and that `restricted` is still refused when option C is not implemented** |
| `tests/test_containment_soundness.py` | the R-6 escape: legacy `clone` into a child user namespace must be **denied** and must not defeat `verify_empty`; dead-pid `inspect` must not erase namespaces or emit a spurious `KILL_FAILED` |
| `tests/test_supervisor_lifecycle.py` | **R-1**: abnormal exit terminates the workload, no orphan, no fabricated `PROCESS_EXITED`; SIGINT and SIGTERM paths; storage-write failure is reflected in the exit code |
| `tests/test_cli_policy.py` | `policy validate/resolve/digest`; all issues reported; exit 2 on invalid; JSON output; **no text after JSON** (fixing the `doctor --json --containment-profile` defect) |
| `tests/test_docs_claims.py` | every capability claim in `docs/*.md` maps to a passing test id or an explicit `NOT IMPLEMENTED` marker; README claims about redaction, observation and duplicate-hash signals match the code |

### 13.3 Existing tests that must stay green

Everything under `tests/`, unmodified except where a change is required and justified:
`test_v2_boundaries.py:374-396` (payload freeze), `test_packaging.py` (contracts),
`test_v3_containment.py` (Linux, `v3` marker). Any modification to an existing test
must be called out in the commit message with the reason.

### 13.4 Malformed input and adversarial input

Extend the existing forging/malformed agents
(`tests/agents/ipc_agent.py`, `tests/agents/malformed_sender.py`) to cover: Policy
V1 documents that are valid JSON but semantically incoherent; a 10 MiB policy file;
a policy with 100 000 deny entries (parse-time and digest-time budget); deeply nested
metadata (depth 6 is enforced, `protocol.py:163-169`); and a policy that is a JSON list
rather than an object.

### 13.5 Platform matrix

CI keeps the existing matrix (`.github/workflows/ci.yml:86-122`: ubuntu-latest and
windows-latest × Python 3.10/3.12/3.14, `-m "not v3"`) and the dedicated
`ubuntu-22.04` V3 job (`133-177`). Additions:

- policy normalization and digest tests run on **both** platforms with an
  identical-digest assertion across them (this is the test that would have caught the
  Windows case-folding divergence);
- a `cgroups` job that asserts the *honest* report on a host without delegation — i.e.
  it may pass without cgroup enforcement, provided `doctor` says `UNAVAILABLE`;
- an anchor job that runs `FileAnchor` and a local `HttpAnchor` stub.

### 13.6 Performance measurement (before any optimization)

`benchmarks/benchmark_v4.py`, following the shape of `benchmarks/benchmark_v2.py` and
`benchmark_v3.py`. Measured and recorded in `benchmark-v4-results.json`: policy parse
time, normalization time, digest time, resolution time, policy evaluation latency,
rate-limit evaluation latency, IPC round trip, PoE append cost, session setup,
containment setup, anchor commit cost, kill latency. **No optimization before the
numbers exist**, and the numbers are published in the README alongside the existing
V1/V2/V3 figures — including the caveat that they describe one machine
(`README.md:293-299`).

---

## 14. Security invariants

Numbered, testable, each with the test that enforces it. These are the properties V4
must be able to state without qualification.

### Decision integrity

- **INV-1** No model, LLM, network call, random source or clock read participates in a
  security decision. → `test_api_objects.py`, `test_sdk_contract.py`, and a static
  import check on `watcher/policy.py`.
- **INV-2** Same normalized request + same resolved policy + same recorded authoritative
  state ⇒ identical decision. → `test_rate_limits_determinism.py`,
  `test_policy_resolver_properties.py`.
- **INV-3** A client cannot supply or influence `sequence`, `timestamp`, `previous_hash`,
  `event_hash`, `final_hash`, `decision` or `risk`. → existing
  `test_ipc_protocol.py:327-393`, extended `test_sdk_contract.py`.
- **INV-4** Every decision is bound to a `resolved_policy_digest` recorded inside the
  hash chain. → `test_policy_v1_digest.py`, `test_rate_limit_poe.py`.
- **INV-5** A killed session authorises nothing; a quarantined session that attempts a
  second blocked action is killed; a kill cannot be undone over IPC. → existing
  `test_watcher.py`, `test_v2_end_to_end.py`.

### Policy

- **INV-6** Unknown keys are rejected at every level; no value is ever coerced into
  validity. → `test_policy_v1_schema.py`.
- **INV-7** A lower layer never weakens an upper-layer restriction: `DENY > ALLOW`,
  `KILL` tripwire > ordinary rules, `restricted` never becomes `open`, numeric ceilings
  are `MIN`-merged, booleans are `AND`-merged, tripwires are `UNION`-only. →
  `test_policy_impossible_weakening.py`.
- **INV-8** The resolved policy digest is independent of the order layers are supplied
  in. → `test_policy_resolver_properties.py`.
- **INV-9** A pattern the engine does not understand is a validation error, never a
  silently non-matching rule. → `test_policy_v1_globs.py`.
- **INV-10** Policy normalization and digests are platform-independent. →
  `test_policy_v1_normalization.py` (cross-platform identical digest).
- **INV-11** Every weakening attempt is recorded, whether or not it succeeded. →
  `test_policy_impossible_weakening.py`.

### Rate limits

- **INV-12** `limit = N` admits exactly requests 1..N in a window; request N+1 is a
  deterministic violation. → `test_rate_limits_boundary.py`.
- **INV-13** Rate-limit accounting is race-free under concurrent requests: the total
  admitted never exceeds the limit. → `test_rate_limits_concurrency.py`.
- **INV-14** A rate-limited action is refused, never delayed; no `sleep()` participates
  in the decision. → `test_rate_limits_determinism.py` (also a grep-based check).
- **INV-15** Every violation is recorded with counter, window, limit, observed, action
  and decision. → `test_rate_limit_poe.py`.

### Containment and enforcement

- **INV-16** An enforcement mode that cannot be honoured is refused, never downgraded;
  the workload is never started unprotected. → existing
  `test_v3_containment.py:507-611`, `test_v3_capabilities.py`.
- **INV-17** No enforcement claim is made unless a real probe succeeded. cgroups and
  egress each report `AVAILABLE`/`PARTIAL`/`UNAVAILABLE`, and an unavailable mechanism
  produces no enforcement event. → `test_cgroup_availability.py`,
  `test_v3_capabilities.py:62,73`.
- **INV-18** No user-space-only or DNS-only control is presented as OS enforcement;
  restricted egress is refused unless kernel-denied default plus an allow-listed path
  are both real. → `test_network_bypass.py`.
- **INV-19** Direct socket bypass is impossible under `restricted` and under `none`. →
  `test_network_bypass.py`, existing `test_v3_containment.py:405-412`.
- **INV-20** Teardown leaves no live descendant: the emptiness verdict is sound
  (PID-namespace-keyed or cgroup-`populated`-based, never a single user-namespace
  inode) and treats an unreadable namespace as not empty. → `test_containment_soundness.py`.
- **INV-21** On abnormal supervisor exit the workload is terminated and the trace
  records what actually happened; no orphan survives and no exit is fabricated. → R-1
  test `test_supervisor_lifecycle.py`.

### Evidence integrity

- **INV-22** An attacker with write access to the trace storage cannot produce a trace
  that passes `TRACE VALID` **and** `ANCHOR VALID` without owning the anchor. →
  `test_verify_anchor.py`.
- **INV-23** `TRACE VALID` and `ANCHOR VALID` are reported separately and never
  collapsed. → `test_verify_anchor.py`.
- **INV-24** A sealed trace missing its declared final hash is invalid; an empty trace
  is invalid. → `test_verify_anchor.py`, `test_tampering.py` extensions.
- **INV-25** The anchor binds session id, event count, final hash and policy digest. →
  `test_anchor.py`.
- **INV-26** Redaction is applied before hashing and covers every field that can carry
  a value, not only `resource`/`metadata`. → extended `test_poe.py`, and a docs-claims
  test asserting README ⇄ code agreement (R-25).

### Interface discipline

- **INV-27** No private internal object leaks into the public API. → `test_api_objects.py`.
- **INV-28** The SDK never decides policy, never owns authoritative time, sequence
  numbers or the PoE, and treats every client field as untrusted. → `test_sdk_contract.py`.
- **INV-29** Enforcement never depends on the SDK; `watcher run --enforced -- cmd`
  contains a workload that never imports Watcher. → new regression test, extending
  `test_v3_containment.py:335`.
- **INV-30** Failure defaults are closed: a supervisor error, a malformed frame, a
  timeout in the decision path, a storage failure or a hook failure never results in an
  allow. → extended `test_ipc_auth.py`, `test_supervisor_lifecycle.py`.

---

## 15. Explicit non-goals

Out of scope for V4, and where relevant, permanently:

1. **No LLM or model in the trusted decision path.** Permanent. Enforced by INV-1.
2. **No blockchain, ledger, token or signature.** Permanent, per the project's
   independence statement (`__init__.py:29-30`). The anchor is an append-only log or a
   generic HTTP sink, nothing more.
3. **No identity layer.** No agent identity, no keys, no certificates.
4. **No ten framework integrations.** Only the generic `WatcherAdapter` contract
   (Phase 5). LangChain, CrewAI, OpenAI Agents and MCP packages come later, outside
   core, with no framework dependencies in `the_watcher`.
5. **No final VUNEUM/docs website.** Internal `docs/*.md` only, honest about status.
6. **No transparent network interception.** V4 does not claim it and does not fake it.
   Option C is a capability restriction, documented as such (§8.3).
7. **No syscall-level policy observation.** `SECCOMP_RET_USER_NOTIF`, `fanotify` and
   eBPF-based observation are research items for V5+. Until then, §7.4 states exactly
   which policy rules require instrumentation and which do not.
8. **No Windows or macOS OS containment.** There is no Landlock/seccomp equivalent;
   V4 keeps the honest refusal and the WSL2 guidance
   (`capabilities.py:177-193`), and does not invent a weaker mechanism to fill the box.
9. **No rewrite of V1/V2/V3.** The core decision path, chain construction, IPC framing
   and drain-before-seal ordering are frozen (§2.3).
10. **No new runtime dependencies.** Zero, permanently, enforced by C-3.
11. **No SaaS control plane, no telemetry, no phone-home.** The anchor is opt-in and
    points wherever the operator says.
12. **No defence against a root/administrator attacker, and no defence against a
    same-user attacker who can read the session token** (`daemon.py:899`). V4
    documents this residual instead of implying otherwise. R-3 removes the *false
    authority* of a client-claimed PID; it does not make the token unforgeable.
13. **No semantic-policy enforcement without instrumentation.** V4 does not claim that
    `deny: /etc/**` stops an uninstrumented agent from reading `/etc/shadow` through
    the *policy engine* — it stops it through **Landlock**. The distinction is stated
    in §7.4 and in `docs/containment.md`.
14. **No optimisation before measurement.** §13.6.
15. **No policy hot-reload mid-session.** A resolved policy is fixed for the session so
    that every decision in a trace shares one `resolved_policy_digest`. Reloading would
    create a trace with two policies and no unambiguous answer to "which policy decided
    this?". If hot-reload is ever wanted, it requires a policy-generation counter on
    every event.

---

## 16. Open design decisions

| # | Decision | Recommendation | Why it matters |
|---|---|---|---|
| **ODD-1** | `Decision` name collision between the existing public enum and the required result object | Put the result object in `the_watcher.api` as `Decision`; do not touch `the_watcher.Decision` (enum). Fallback: name it `DecisionResult` | Getting this wrong either breaks V1/V2/V3 imports or diverges from the brief's vocabulary. Needs an explicit sign-off. |
| **ODD-2** | Anchored payload contents | `{schema_version, session_id, event_count, final_hash, policy_digest}`, domain-separated | Affects replay resistance and whether policy and evidence can be separated. |
| **ODD-3** | Policy file format | **JSON normative in Phase 1**; strict YAML subset in Phase 2 behind a parser-conformance suite. The digest is always computed over canonical JSON | A hand-rolled YAML parser is the largest new attack surface V4 would add, and the brief itself flags parser ambiguity as a risk. The brief's examples are YAML, so this is a real trade-off. |
| **ODD-4** | Rate-limit windowing default | Fixed window, with the documented ≤2× boundary behaviour; deterministic sliding window available per-policy | Fixed is simplest to reason about and reproduce; sliding removes the burst but adds state. Both are deterministic. |
| **ODD-5** | Should Policy V1 `network.mode: open` be allowed at all? | Permit, but make `is_reduced_protection` loud and require an explicit flag | `open` shares the host stack; the mission wants restricted-not-open, and an accident here silently removes containment. |
| **ODD-6** | Whether `restricted` egress ships in V4 at all | Ship option C, or **keep refusing** and say so | Shipping a cooperative proxy labelled "OS-enforced egress" would be exactly the overstatement the mission forbids. Keeping the refusal is a legitimate V4 outcome. **Requires a product decision.** |
| **ODD-7** | Legacy policy dispatch on absence of `version` | Accept the legacy V3 shape, with `--policy-format` to remove the inference | Convenient, but "absence means legacy" is an inference where the project's stated preference is explicitness. Needs sign-off. |
| **ODD-8** | Is a trace byte budget a policy rule or a supervisor self-protection limit? | Supervisor limit, recorded as a supervisor event, not a policy denial | A client must not be able to make the supervisor OOM (R-14), but calling it a policy rule would misattribute it in the audit. |

---

## 17. Files V4 would add and change

Nothing below has been created or modified except `docs/V4_DESIGN.md`.

### New

```
docs/V4_DESIGN.md                  this document
docs/architecture.md               §1 + §2, kept current
docs/policy.md                     §4 + §5, with the full schema reference
docs/integration.md                §7 + adapter contract
docs/sdk.md                        §7.5
docs/containment.md                §8 + §9 + the §7.4 zero-code truth table
docs/poe.md                        §10 + the tamper model
docs/threat-model.md               §14 + §15 residuals
docs/production.md                 §13.6 + deployment/gotchas
docs/network-egress-decision.md    §8 as a standalone decision record

the_watcher/policy_v1.py            schema, validation, normalization, globs, digests
the_watcher/layers.py               PolicyLevel/Layer/Resolver/ResolvedPolicy/Conflict
the_watcher/limits.py               counter model, windows, deterministic accounting
the_watcher/api/__init__.py         ActionRequest, Decision, DecisionReason,
                                    SessionInfo, PolicyInfo
the_watcher/api/client.py           public WatcherClient wrapper
the_watcher/adapters/__init__.py    WatcherAdapter.before_action/after_action/on_error
the_watcher/poe/anchor.py           Anchor protocol, FileAnchor, HttpAnchor, NullAnchor
the_watcher/enforcement/linux/cgroup_limits.py   guard-side cgroup verification
the_watcher/enforcement/egress.py   supervisor-owned egress broker (if ODD-6 says yes)

tests/test_policy_v1_schema.py
tests/test_policy_v1_globs.py
tests/test_policy_v1_normalization.py
tests/test_policy_v1_digest.py
tests/test_policy_layers.py
tests/test_policy_impossible_weakening.py
tests/test_policy_resolver_properties.py
tests/test_rate_limits_boundary.py
tests/test_rate_limits_determinism.py
tests/test_rate_limits_concurrency.py
tests/test_rate_limit_poe.py
tests/test_api_objects.py
tests/test_sdk_contract.py
tests/test_adapter_contract.py
tests/test_anchor.py
tests/test_verify_anchor.py
tests/test_cgroup_availability.py
tests/test_network_bypass.py
tests/test_containment_soundness.py
tests/test_supervisor_lifecycle.py
tests/test_cli_policy.py
tests/test_docs_claims.py

benchmarks/benchmark_v4.py
```

### Changed

```
the_watcher/watcher/matching.py     + glob engine (validation, *, **, ?)
the_watcher/watcher/policy.py       unchanged behaviour; legacy loader retained
the_watcher/watcher/watcher.py      + rate-limit consultation point (order per §5.4)
the_watcher/poe/event.py            + new EventType members (payload keys frozen)
the_watcher/poe/verifier.py         + anchor verdicts; R-4/R-5 fixes
the_watcher/ipc/protocol.py         + ErrorCode for rate limiting; validate all limits
the_watcher/ipc/server.py           + limiter at _begin_write; fix replay-cache race
the_watcher/ipc/client.py           + public wrapper; keep fail-closed default
the_watcher/supervisor/daemon.py    R-1 orphan/termination fix; limiter accounting;
                                    policy digest in SESSION_START metadata;
                                    anchor commit after seal; TRACE_SEALED count fix;
                                    storage-failure exit code
the_watcher/enforcement/capabilities.py   real cgroup delegation probe; egress verdict;
                                          arch-correct seccomp probe (R-13)
the_watcher/enforcement/profile.py        map cpus to cpu.max; make dropped knobs real
                                          or remove them (R-7/R-18)
the_watcher/enforcement/base.py           SandboxSpec cgroup path; stronger verify_empty
the_watcher/enforcement/backends/namespaces.py  network=open self-refusal fix;
                                          R-6/R-8/R-9/R-10/R-11/R-12; cgroup wiring;
                                          egress broker wiring (ODD-6)
the_watcher/enforcement/linux/exec_guard.py     cgroup step; report["cgroup"]
the_watcher/enforcement/linux/seccomp_filter.py block legacy clone; fix dead knobs
the_watcher/cli.py                  + policy subcommand group; + --anchor;
                                    catch ContainmentRefused cleanly (R-24)
the_watcher/__init__.py             + WatcherClient export; __version__ 0.4.0
pyproject.toml                      version 0.4.0
tests/test_packaging.py             widen the subcommand regex to include `policy` (C-2)
README.md                           correct R-7/R-25/R-26 claims; document V4 status
                                    honestly, including what is NOT implemented
```

---

## 18. Baseline verification for this design

Recorded before any V4 code exists, so the baseline is unambiguous.

- **Commit:** `070f64271dacb17633b15ed867968344a5d1d94d`, branch `v4`, working tree clean
  except this document.
- **Test suite:** `python -m pytest -q` — **exit code 0**. `521 collected, 460 passed,
  61 skipped in 71.87s` on Windows / Python 3.14.3. Skips are the platform-gated V3 containment
  suites (`tests/test_v3_containment.py`, `pytestmark = requires_enforcement() + v3`
  at line 35) plus Linux-only `skipif` cases; the dedicated `ubuntu-22.04` CI job owns
  those (`.github/workflows/ci.yml:133-177`).
- **Quality gates:** `python -m ruff check .` → *All checks passed*;
  `diagnostics/check_code_hygiene.py` → 0 findings;
  `diagnostics/check_text_hygiene.py` → 91 files, 0 issues;
  `diagnostics/secret_scan.py` → no live credential shapes.
- **Environment note:** the shell sandbox on this host could not start (its temp
  directory was missing), which made subprocess-spawning tests fail with
  `PermissionError [WinError 5]`. Re-running with full access reproduced the clean
  result above. The failures were an artifact of the sandbox, not of the repository;
  they are noted here so the numbers above are not mistaken for a first-try clean run.

---

## 19. Phase 0 record — V3 trust-boundary hardening

Phase 0 fixed the security-relevant defects found by the audit in shipped V3,
in isolation, before any V4 feature work. It changed **no public API, no CLI
flag, no exit code and no PoE event field**.

### 19.1 Blocker A — finalisation must not orphan the workload

**Root cause.** `WatcherDaemon._finalize` destroyed containment, drained IPC,
recorded lifecycle events and sealed the trace, but never terminated the
workload. `terminate_tree` appeared only in kill accounting. Every path that did
not already observe an exit — a supervisor exception, a keyboard interrupt, a
signal, or a stop request that could not kill — reached `_finalize` with the
workload still running, and then wrote
`PROCESS_EXITED … "protected process exited with {exit_code}"` for a process
whose exit was never observed. The workload was left detached
(`start_new_session=True`) with no signal handler anywhere to intervene.

**Fix.** `_finalize` now establishes liveness first, via
`_ensure_workload_stopped`, which returns exactly one of `not_started`,
`already_exited`, `terminated` or `termination_unverified`, and an
`exit_observed` flag. A live workload is recorded (`SHUTDOWN_REQUESTED`,
`TERMINATION_INITIATED`), terminated through the containment unit or the
supervisor's own process handle, and then **verified** with a bounded `wait()`.
`PROCESS_EXITED` is written **only** when an exit was actually observed. An
unverifiable termination is recorded as `TERMINATION_UNVERIFIED` at `CRITICAL`,
the session ends `FAILED`, and no exit event is written.

**Invariant now enforced.** A session is never finalised or sealed as exited
while its protected workload is alive, and no lifecycle event asserts an
observation that was not made. Finalisation remains idempotent, and the
drain-before-seal sequencing is untouched.

### 19.2 Signals

`WatcherDaemon.request_shutdown` records why a stop was asked for and wakes the
supervision loop; the loop then performs the ordinary recorded kill under the
normal lock. The CLI installs `SIGINT`/`SIGTERM` handlers through
`supervisor_signal_handlers`, in the main thread only, restoring the previous
handlers afterwards; failures to install are ignored so Windows behaviour is
unchanged. No asynchronous cleanup happens inside a signal frame.

### 19.3 Blocker B — containment-unit identity and `verify_empty`

**Root causes.** (1) `NamespaceEnforcer.inspect` assigned a fresh `/proc` read
onto `unit.namespaces`; when the pid was dead that read was empty, so the
identity was erased by the very event it is needed for. (2)
`verify_empty`/`_unit_processes` returned *no survivors* when there was no
namespace to look for — a fail-open answer that reported a sandbox as empty
precisely when it could not tell. (3) A descendant that created a child
namespace carried neither the unit's user- nor PID-namespace inode and was
invisible to a single-inode scan.

**Fix.** `ContainmentIdentity` records the launcher pid, sandbox pid, both start
times (the PID-reuse guard), the namespace inode set and the cgroup, **once**, at
launch; `inspect` no longer overwrites it with an empty read; `contained
scan_survivors` combines four independent layers — PID namespace, user
namespace, ancestry from the launch-time roots, and cgroup membership — and
`verify_empty` fails closed when the identity is unknown.

**Invariant now enforced.** An unverifiable unit is never reported as empty, a
descendant that changes namespaces is still found, and a recycled pid is not
mistaken for a unit ancestor. **Not solved here:** cgroup-backed emptiness
(`cgroup.events populated=0`), which is the independent proof Phase 7 adds.

**Proven on Linux, not assumed.** §19.8 records an adversarial lifecycle
executed against a real sandbox. Two findings matter:

* the **legacy `clone` syscall is not in the seccomp denylist** (`unshare`,
  `setns` and `clone3` are), and it does create nested user/PID/mount
  namespaces from inside a contained workload;
* the identity's **inode layer is therefore defeated by construction** — the
  nested child's `user`, `pid` and `mnt` inode values all differ from the unit's.

What finds such a survivor is the **ancestry layer**, and that rests on a kernel
property worth naming explicitly: inside a PID namespace every orphan re-parents
to that namespace's init, which is a recorded ancestry root. A process belonging
to the unit therefore cannot leave the PPID graph rooted at the sandbox init,
however many child namespaces it creates. That is why the layered scan is
load-bearing rather than decorative.

### 19.4 Blocker C — authority of the facts a decision is built from

**Root cause.** The engine read almost every fact it judged from client
`metadata`, and `metadata["path"]` **overrode** the `resource`. A client could
send `resource="/etc/shadow"` — the value written into the trace — with
`metadata={"path": "/workspace/harmless.txt"}`, and the path rule would check
the harmless file while the audit record showed the dangerous one.

**Fix.** `the_watcher/watcher/authority.py` classifies every policy input as
`AUTHORITATIVE`, `OBSERVED` or `CLIENT_ASSERTED`, and states the governing rule:
*a client assertion may only ever add restriction*. Rules with more than one
candidate value are evaluated against all of them and the strictest verdict
wins. The supervisor now publishes the facts it can genuinely establish
(`resource`, a measured `process_count`, an observed `runtime_seconds`) in a
reserved `metadata.authoritative` namespace, written last; a client that tries to
write that namespace is recorded as having done so. Decision events carry a
`fact_authority` map showing which facts the verdict rested on.

**Invariant now enforced.** Forged client metadata cannot override a trusted
host fact or weaken a verdict derived from one. Facts that cannot be observed
without cooperative instrumentation (`privilege_escalation`, `persistence`,
`host_resource`, `env_var`) are **labelled cooperative rather than
authoritative** — they are not promoted, and no host fact is invented for them.

### 19.5 Blocker D — declared versus enforced configuration

**Root cause.** The profile digest hashed the *declaration*. `resources.cpus`
defaulted to `1.0`, was printed by `summary()` and entered the digest, and no
backend except Docker ever consumed it;
`no_new_privileges`/`drop_all_capabilities`/`add_capabilities` were read by
nothing at all.

**Fix.** `the_watcher/enforcement/declared.py` produces a per-field,
per-backend verdict (`ENFORCED` / `PARTIALLY_ENFORCED` / `UNSUPPORTED` /
`REFUSED`). `resources.cpus` now defaults to `None` ("not configured"). The rule
is the difference between silence and intent:

* **not specified** — no ceiling was asked for, so running without one is
  correct and nothing is raised;
* **explicitly specified but unsupported** — a CPU rate the namespace backend
  cannot apply is **REFUSED at `prepare()`, before the workload is launched**.
  `no_new_privileges=False`, `drop_all_capabilities=False`,
  `add_capabilities=(…)`, `allowed_networks` without `restricted`, and
  `network=restricted` are refused the same way.

`allow_reduced_protection` is the explicit, recorded opt-in for a caller who has
decided to run without such a control. It is a **profile field**, so it is
covered by the profile digest, and it can never waive a setting in
`NEVER_OVERRIDABLE` (`network`, `no_new_privileges`, `drop_all_capabilities`,
`add_capabilities`, `allowed_networks`) — accepting those would not mean "running
without a control", it would mean recording a posture the kernel does not
implement, which is the defect this phase removes. Both backends call
`require_honourable`, and `CONTAINMENT_PREPARED` records the full report, the
declared-but-unhonoured list, a `reduced_protection` flag and the waiver
**beside** the digest. `watcher doctor --containment-profile X` prints the same
report. The `network=open` self-refusal — which made every non-`none` posture
impossible to complete — is fixed: `open` is a declared posture that is applied
faithfully and recorded as reduced protection, not a containment failure.

**Invariant now enforced.** No configuration value may be presented as enforced
configuration while the selected backend silently ignores it: every unhonoured
setting is either refused before launch, or explicitly accepted with a recorded
waiver.

### 19.6 PoE

Four deterministic event types were added —
`shutdown_requested`, `termination_initiated`, `termination_verified`,
`termination_unverified` — so that a termination outcome is stated as what was
observed rather than inferred. The event payload key set and
`schema_version = "watcher-poe/1"` are unchanged. `TRACE_SEALED` now records the
event count of the sealed trace rather than one event short.

### 19.7 Phase 0 limitations

- **cgroup-backed enforcement and emptiness proofs** are not implemented; the
  namespace-inode and ancestry layers are what make `verify_empty` sound today.
- **Cooperative policy rules** (`privilege_escalation`, `persistence`,
  `host_resource`, `env_var`) remain client-asserted. They are now labelled, not
  fixed; closing this needs syscall-level observation, which is out of scope.
- **`resources.cpus` is not enforced** on the namespace backend. It is refused
  before launch unless the operator waives it; real enforcement needs cgroup v2.
- **The container backend applies very little of a profile** (24 fields are
  reported `UNSUPPORTED`). It remains experimental and unverified.
- **The legacy `clone` namespace flags are denied, but `clone` itself is not.**
  The argument-aware rule blocks `CLONE_NEW*`; a future kernel that adds a
  namespace-creating flag outside the audited mask would need the mask extended.
  Phase 0 detects such a survivor rather than assuming it cannot exist, which is
  why the layered scan is kept as defence in depth.

### 19.8 Linux validation evidence

Executed under WSL2 (Ubuntu 24.04, kernel `6.6.87.2-microsoft-standard-WSL2`,
x86-64, Python 3.12.3) on a Linux-native (`ext4`) workspace, with the namespace
backend selected and a seccomp filter confirmed active (`seccomp_mode: 2`).
`diagnostics/probe_namespace_primitives.py` was added as the reproducible probe.

**1. Which enforcement stops which primitive.** Measured inside the sandbox:

| Primitive | Result inside the sandbox | Standalone (control) |
|---|---|---|
| `unshare(CLONE_NEWUSER)` | `EPERM` | succeeded |
| `unshare(CLONE_NEWPID)` | `EPERM` | `EPERM` (kernel, no CAP_SYS_ADMIN) |
| `unshare(CLONE_NEWNS)` | `EPERM` | `EPERM` (kernel) |
| `clone3(CLONE_NEWUSER\|CLONE_NEWPID\|CLONE_NEWNS)` | `EPERM` | did not complete |
| **legacy `clone(CLONE_NEWUSER\|CLONE_NEWPID\|CLONE_NEWNS\|…\|SIGCHLD)`** | **succeeded** | succeeded |

The user-namespace control is the load-bearing one: `unshare(CLONE_NEWUSER)`
**succeeded standalone and returned `EPERM` inside the sandbox**, so the refusal
is the seccomp filter and not the kernel's privilege rules. The legacy `clone`
row is the finding: the syscall is absent from every seccomp table, so it carries
the same namespace flags past the filter.

**2. The adversarial survivor is real.** The lifecycle
`sandbox init → descendant → descendant creates nested namespaces with legacy clone
→ ancestor exits → nested child re-parented and still alive` was executed inside
the sandbox. Observed from inside the unit:

```
nested.ok                          = true
nested.child_state                 = "S"          (alive, not a zombie)
nested_reparented_to               = 1            (the sandbox init)
nested_state_after_ancestor_exit   = "S"
nested_live_namespaces.user        = user:[4026532362]   unit: user:[4026532224]
nested_live_namespaces.pid         = pid:[4026532366]    unit: pid:[4026532302]
nested_live_namespaces.mnt         = mnt:[4026532363]    unit: mnt:[4026532225]
```

**3. `verify_empty` found it.** With that survivor alive, `scan_survivors`
returned `empty = False` and `survivors = (launcher, sandbox_init, nested_child)`;
the child — identified on the host by its own PID-namespace inode — was in the
list. The layer that found it was **ancestry**, which is the point: the
PID-namespace and user-namespace layers both missed it, exactly as the escape
intends. After `terminate()`, `verify_empty` returned `True` with no survivors.

**3b. The primitive is now denied, not merely detected.** Phase 0 closes the gap
with an argument-aware seccomp rule on `clone`:

```
ld  nr
jeq <clone>, 0, 4          ; not clone -> skip this whole block
ld  args[0] low 32 bits
and 0x7E020080             ; CLONE_NEW* mask, audited from <linux/sched.h>
jeq 0, 1, 0                ; no namespace bit -> allow
ret ERRNO|EPERM
```
plus a second block on the high 32 bits that denies the clone3-era flags
(`CLONE_CLEAR_SIGHAND`, `CLONE_INTO_CGROUP`) while still allowing a
sign-extended negative `int` flags word, so a legitimate `CLONE_IO` caller is
not broken. The mask is `0x7E020080` = `CLONE_NEWTIME | CLONE_NEWNS |
CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID |
CLONE_NEWNET`; the flag *values* are UAPI and identical on every architecture,
so only the syscall number is per-arch (`clone` = 56 on x86-64, 220 on aarch64).
Re-measured inside the sandbox: `legacy_clone_nested.ok = false`,
`errno_name = EPERM`, `child_pid = null`.

**3c. A pre-existing defect this exposed.** `clone` could not simply be added to
the denylist, because glibc's `__clone_internal` falls back from `clone3` to the
legacy syscall **only when `clone3` returns `ENOSYS`** — any other errno is
taken as a real refusal. V3 denied `clone3` with `EPERM`, which meant
`pthread_create` failed inside the sandbox with *"can't start new thread"*, on
unmodified V3 code (reproduced with the new clone guard disabled, and with the
process ceiling raised, so it was not the rlimit). `clone3` is now denied with
`ENOSYS`, which is both the answer glibc's documented fallback expects and the
more honest one: the filter makes the syscall look unavailable, and the legacy
path it falls back to is guarded on its flags. Threaded and subprocess workloads
were re-measured inside the sandbox afterwards: 8/8 threads ran and
`subprocess.run` returned its output.

**4. A defect this run exposed and Phase 0 fixed.** The cgroup layer had recorded
the *ambient* cgroup (the systemd slice, or `/` under a cgroup namespace), which
is shared with the supervisor and with unrelated system processes. The first
Linux run reported `processes survived containment: [1, 2, 6, 225]` — pid 1 and
other host processes — for every terminated unit. The namespaces backend now
records `cgroup=None` (it does not create a per-unit cgroup), and the scan skips
the layer when the recorded cgroup is the supervisor's own. This could not be
found on Windows: `/proc` and cgroup semantics simply do not exist there.

**4b. `final_check.sh` corrected.** Its section 4 pointed `--workspace` at the
repository and printed the resulting exit code as though it were a refusal. On an
ext4 checkout the repository *is* containable, so the step exited 0 and proved
nothing while looking like a pass. It now looks for a genuinely uncontainable
mount (9p/drvfs/network filesystem) and either exercises the refusal and asserts
exit 78, or prints `SKIPPED: no known uncontainable workspace available on this
host` together with the name of the pytest regression that does cover it. It no
longer reports success for a negative case it never exercised.

**5. Results.**

| Run | Result |
|---|---|
| `python -m pytest` (Linux, full, run 1) | **661 passed, 2 skipped** (exit 0) |
| `python -m pytest` (Linux, full, run 2) | **661 passed, 2 skipped** (exit 0) |
| V3 modules only | **117 passed, 2 skipped** (exit 0) |
| `bash diagnostics/final_check.sh` | **exit 0** — doctor reports `namespaces AVAILABLE`, `landlock reach: yes`, `ext4`; the enforced network run reports all six attempts `DENIED` (`ENETUNREACH`, `gai:-3`); section 4 reports `SKIPPED` honestly; V2 supervision still works |
| `python diagnostics/probe_namespace_primitives.py` | exit 0 |
| `python -m ruff check .` | All checks passed |
| `check_code_hygiene.py` | 0 findings |
| `check_text_hygiene.py` | 100 files, 0 issues |
| `secret_scan.py` | no live credential shapes |
| `git diff --check` | exit 0 |
| `python -m pytest` (Windows, full) | **593 passed, 70 skipped** (exit 0) |

The 2 Linux skips are the platform-conditional assertions in
`tests/test_v3_capabilities.py` (lines 56 and 308), which are about *non*-Linux
hosts and about the namespace backend being unavailable — neither applies here.
The adversarial tests are **not** among the skips: they ran.

**6. One pre-existing flaky test, not caused by Phase 0.**
`tests/test_ipc_shutdown.py::test_a_request_arriving_during_drain_is_refused_not_dispatched`
fails intermittently: 1 failure in 6 runs on the Phase 0 tree, and 1 failure in
10 runs of a pristine `git archive HEAD` copy of the base commit. It is a
timing-sensitive drain test that Phase 0 does not touch. Recorded here rather
than papered over; it is a pre-existing defect worth its own fix.

---

## 20. Phase 1 record — Policy V1 document format

Delivered: `the_watcher/policy_v1.py`, `watcher policy validate|digest`,
`docs/policy.md`, `tests/test_policy_v1.py`, `benchmarks/benchmark_policy_v1.py`.

Phase 1 builds the **document boundary** and stops there. It evaluates nothing,
enforces nothing, and is not wired into `watcher run`.

### 20.1 Decisions taken against the original §4 sketch

Three departures from the design sketch, each to avoid a field meaning two
things at once — the collision audit the brief asked for:

| Sketch | Phase 1 | Why |
|---|---|---|
| `resources.pids` | **rejected**, pointed at `process.max_children` | the containment profile already calls the process ceiling `processes.max_processes`; a third name (`resources.pids`) for one ceiling gives it three meanings. Refused with an error naming the right field. |
| `network.allow` as CIDRs | **hostnames only**; CIDRs refused | `ContainmentProfile.allowed_networks` already holds CIDRs for the OS backend. The same-looking field in two vocabularies is exactly how a policy ends up meaning the opposite of what its author read. |
| `on_violation` classes `forbidden_file`, `rate_limit`, `resource_limit`, `process_limit` | `filesystem`, `network`, `process`, `resources`, `tripwire` | the sketch's names mixed rule-level and mechanism-level concepts, and `rate_limit` belongs to Phase 3. Classes that do not exist yet are refused rather than reserved. |

Also settled: `name` defaults to `"default"`, matching the existing V3
`Policy.name` default, rather than introducing a second default vocabulary.

### 20.2 The `**` defect, and why glob syntax is a security fix

V3's matcher has no glob support at all: `any_path_matches` compares path
*components* with `path_is_within` (`watcher/matching.py:57-73`), so
`"/etc/**"` is compared as a literal segment. The result is that the design
document's own example — `deny: ["/etc/**"]` — **matches nothing**, and a rule
that matches nothing is indistinguishable from a rule that works.

Phase 1 implements a deliberately tiny grammar (`*` within a segment, `**` as
whole segments, `?` for one character, literals) and **refuses** everything
else: `[`, `]`, `{`, `}`, `!`, `\`, and partial-segment `**` such as `a**b`.
Bare literal paths keep V3's implicit-subtree meaning, so existing semantics are
preserved rather than reinterpreted; `/a/**` is added as the explicit spelling of
the same thing, which can only *add* restriction relative to today's
matches-nothing behaviour.

**No shared code was changed.** `watcher/matching.py` is untouched, so there is
no path by which Phase 1 can alter V1/V2/V3 behaviour.

**What that means at runtime, concretely.** Because Policy V1 is not wired in,
`watcher run --policy` still evaluates with V3's matcher, so a rule written
`/etc/**` still matches nothing today and `/etc/*` is still a literal. Phase 1
fixes the *format*, not the runtime; the runtime changes only when a later phase
projects the evaluator onto it. V3 runtime semantics are unchanged.

### 20.3 Decisions that follow from determinism

- **No `~` or `$VAR` expansion.** Expanding either makes one document mean
  different things on different machines, which breaks the digest's whole
  purpose. Refused with an explanation.
- **`..` is refused, not resolved.** Lexical collapsing changes the rule
  (`/workspace/../etc` becomes `/etc`), and resolving it properly needs the
  filesystem, which matching must never consult.
- **Case is never folded.** The same bytes produce the same digest on Windows
  and Linux, which is what makes cross-platform policy comparison mean anything.
- **Rule order is not significant**, and the canonical form sorts and
  de-duplicates rule lists. Policy V1 has no first-match-wins rule: deny and
  is-restricted win over allow. (V3's engine *is* ordered internally; Phase 2
  owns proving the projection preserves these semantics.)
- **Absent section == defaults written out**, so the two share a digest. Fields
  that are "not configured" by default (`resources.memory_mb`,
  `resources.cpu_seconds`) are omitted from the canonical form rather than
  rendered as `null`, so the canonical form never contains a null.

### 20.4 Duplicate keys

`json.loads` silently keeps the *last* of duplicate keys, so
`{"filesystem": {...}, "filesystem": {...}}` discards a rule set without a word
— the author and the engine disagree and nothing says so. Phase 1 installs an
`object_pairs_hook` that rejects a repeated key at every level, plus
`parse_constant` to refuse `NaN`/`Infinity`/`-Infinity`. A test asserts that the
plain parser really would have accepted the duplicate, so the premise is
checked rather than assumed.

### 20.5 Digest

```
document_digest = SHA256("watcher-policy-document/1" + 0x00 + canonical_json(normalized))
```

Built on the existing `poe/canonical.py` encoder, so it is the same
determinism substrate the Proof of Execution uses, with a domain separator so a
policy digest can never be confused with an event hash.
`watcher-policy-resolved/1` is **exported as a reserved constant and deliberately
not produced**: a resolved digest must describe the merged policy, and returning
the document digest under that name would misstate which policy was in force. A
test asserts `PolicyV1` has no `resolved_policy_digest` attribute.

### 20.6 Honest status

Nothing in Policy V1 is runtime-enforced, and the format is not wired into
`watcher run` — feeding a Policy V1 document to `watcher run --policy` fails
loudly, which the test suite asserts. `the_watcher.policy_v1.ENFORCED_IN_PHASE_1`
carries the per-section status in code and a test asserts it still says "no
runtime enforcement", so the documentation cannot drift ahead of the
implementation. `the_watcher.enforcement.declared` remains the authority on what
a backend actually enforces.

### 20.7 Measured cost

`benchmarks/benchmark_policy_v1.py`, medians over 60 repeats on Windows /
Python 3.14.3 and on Linux / Python 3.12.3. The hosts were contended (the max
column ran 4-100x the median), so these are order-of-magnitude figures. One
apparent anomaly — `parse_policy` measuring *slower* than `loads_policy`, which
includes JSON parsing — was resolved by an interleaved A/B measurement
(274 µs vs 245 µs, ratio 0.89), so it was measurement order, not overhead.

| Measurement | Windows median | Linux median |
|---|---|---|
| `loads_policy` (in memory) | ~330-380 µs | ~273 µs |
| `parse_policy` | ~320-470 µs | ~245 µs (interleaved) |
| `load_policy` (from file) | ~1.3 ms | ~363 µs |
| cached `document_digest` | ~0.6 µs | ~0.2 µs |
| `canonical_encode` | ~145 µs | ~48 µs |
| one `PathPattern.matches` | ~9-12 µs | ~7 µs |
| 1000-rule document | ~12-26 ms | ~9 ms |

Startup cost is negligible for a realistic document. The number to carry into
Phase 2 is the match cost: `matches()` re-validates its subject on every call —
deliberately, because a matcher must not answer "no match" to a question it
cannot parse — so Phase 2 should canonicalise the subject **once per action**
rather than once per rule, or a 50-rule policy costs ~0.5 ms per action.

### 20.8 Adversarial matcher review

The matcher is the one part of Policy V1 that will later run on input the
*supervised agent* controls — the path it is trying to touch — while the pattern
comes from the operator. That asymmetry makes the matcher's cost a security
property, not a performance detail, so it was reviewed adversarially.

**Defect found: quadratic backtracking with an attacker-influenced operand.** The
original `_segment_matches` used the classic single-backtrack-point algorithm: on
a mismatch it reset to the last `*` and re-scanned the entire pattern tail. Cost
therefore grew with pattern × subject, and it was reachable through the public
API. `"/" + "*" + "?" * 2040` matched against a 4095-character subject — both
inside the existing caps — cost **1678 ms of CPU for a single match attempt**.
A supervised agent that picks its own paths could repeat that per rule per
action; at the 4096-rule cap that is hours of supervisor CPU. Two shapes reached
this class (`*` followed by a long `?` run, and a long `?` segment after `**`).

**Fix.** The pattern is now split on `*` into `*`-free blocks of fixed length.
The head block is anchored to the start of the subject, the tail block to its
end, and interior blocks are located left to right, earliest first — optimal
because a fixed-length block placed earlier never removes room a later block
needs. Literal blocks are located with a C-level substring search and `?` blocks
with a bit-parallel (Shift-And) scan whose per-character work happens in C. The
guarantee is no longer "the pattern is small", it is "no input shape produces
superlinear *re-scanning*".

**Result.** The 1678 ms shape now costs **51.7 µs** (≈32,000×), and the same
input timed against the old algorithm in-process took 1768 ms against 0.173 ms
for the new one. The worst adversarial shape measured at the caps is now
**586 µs** — a pattern carrying 1020 stars, where the residual cost is one
iteration per block, i.e. linear in the pattern length, not in a product.

**Segment level: bounded, not combinatorial, and one wrong claim removed.** The
`**` matcher had been documented as memoising element comparisons "because
backtracking revisits the same (pattern, text) pair". That justification is
false, and it was measured rather than argued: instrumenting the shipped function
via `inspect.getsource` and recording every `(pattern_position, subject_position)`
pair found **zero revisits** across all cap-sized adversarial shapes, an
exhaustive sweep of small inputs, and a 6000-case randomised search at the caps.
Every walk that follows a backtrack runs along a fresh diagonal, so the loop
never re-enters a state. The cache could therefore never hit, and was removed: it
was the only structure whose size grew with pattern × subject, so the matcher's
extra memory is now constant at the segment level and proportional to the pattern
at the character level.

**The state bound, corrected.** The first version of that paragraph stated the
bound as `P × T` (pattern segments × subject segments). That is **false as an
absolute bound**, and the same instrumentation that disproved the memo disproved
it: with `P = 1` and `T = 77` — a lone `**` against 77 segments — the loop visits
**78** states, entering once to read the `**` and then once per following
position. `78 > 77`. The proven bound is **`(P + 1) × (T + 1)`**, from a
potential-function argument now recorded on `_segments_match`
(`Φ = (T − mark)(P + 1) + (P − pi)`, lowered by at least one by every branch, from
`T(P + 1) + P`): at most 257 × 257 = 66,049 states under the caps, with the
measured worst at 16,512. Asymptotically the cost is still **`O(P × T)`**, since
`(P + 1)(T + 1) = PT + P + T + 1` — so the complexity claim stands while the
finite bound is now one that is actually true for every valid input. The
deterministic test asserts the proven bound over the state-space edges (`P = 0`,
`T = 0`, `P = T = 1`, only `**`, trailing `**`, empty subject, one pattern segment
against a long subject, the terminal transition) and pins the `P = 1, T = 77`
counterexample so the naive form cannot creep back. The benchmark prints
`(P + 1)(T + 1)`, not `P × T`.

Reaching the measured worst case needs a hand-written pattern carrying 128 `**`
segments and 128 `?` segments; a realistic policy is microseconds.

**Correctness was not taken on trust.** Both rewritten levels were differentially
tested against a deliberately exponential brute-force reference: 42,315
character-level cases and 86,831 segment-level cases, exhaustive over small
alphabets, **0 mismatches**. That differential test is now a permanent test, as
is a wall-clock ceiling on every adversarial shape — the ceiling the old
implementation fails by ~7×, so the defect cannot return unnoticed.

**Second finding: lone surrogates.** A pattern written with a JSON `\uD800`
escape produced a Python string containing a lone surrogate. It was accepted,
hashed into the digest, and could never match a path decoded from UTF-8 — a rule
that silently matches nothing, which is the exact failure mode this format
refuses everywhere else. Lone surrogates are now refused in patterns **and** in
subjects (code `lone_surrogate`), with a located error. Real characters above
U+FFFF, including those written as a surrogate *pair*, are unaffected.

**Malformed UTF-8 was already correct, and is now pinned.** Every malformed
encoding tried — lone continuation byte, truncated sequence, overlong encoding,
CESU-8 surrogate, invalid start byte, truncation at EOF — surfaces as a
`PolicyParseError` naming the byte offset, and 3000 fuzzed byte strings produced
no other exception type. `load_policy` indexes `raw[exc.start]`, so the fuzz
also covers the possibility of an out-of-range offset. A 300-case fuzz test and
a parameterised offset test are now in the suite.

**Cost regression fixed while reviewing.** The surrogate check was first written
as a per-character Python loop, which added ~1.4 ms to every subject validation
at the length cap. Both character checks (controls and surrogates) are now one
compiled regex scan, which is what it should have been: subject validation at the
cap is back to ~0.09 ms total. A Python-level loop over a 4096-character subject
costs more than the match it guards.

**Documentation corrected.** `PathPattern` claimed "total matching semantics",
which was false — matching raises on a subject it cannot canonicalise, which is
the point. The grammar doc now says matching is total over *canonical* subjects
and refuses the rest. `docs/policy.md` gained §4.3 (cost), a lone-surrogate row
in the refusal table, and an explicit statement that Unicode normalisation is
**not** applied: NFC and NFD spellings are different rules, so a rule copied from
a normalising editor will not match a differently-encoded path. That behaviour
was previously undocumented, which made it a trap rather than a decision.

---

**V4 DESIGN READY FOR REVIEW — NO IMPLEMENTATION, NO COMMIT, NO PUSH.**

**V4 PHASE 0 READY FOR SECURITY REVIEW — NOT COMMITTED, NOT PUSHED.**

**V4 PHASE 1 POLICY V1 READY FOR REVIEW — NOT COMMITTED, NOT PUSHED.**

**V4 PHASE 1 FINAL SECURITY REVIEW READY — NOT COMMITTED, NOT PUSHED.**
