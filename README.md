<p align="center">
  <img src="public/logo.svg" width="220" alt="The Watcher logo">
</p>

<h1 align="center">The Watcher</h1>

<p align="center">
  <strong>A deterministic runtime security layer for autonomous AI agents.</strong>
</p>

<p align="center">
  <a href="https://github.com/ladebw/the-watcher/actions/workflows/ci.yml"><img src="https://github.com/ladebw/the-watcher/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="#install"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/runtime%20dependencies-0-brightgreen" alt="Zero runtime dependencies">
  <img src="https://img.shields.io/badge/platform-Linux%20%C2%B7%20Windows-lightgrey" alt="Platform: Linux and Windows">
  <img src="https://img.shields.io/badge/status-experimental-orange" alt="Status: experimental">
  <img src="https://img.shields.io/badge/release-v0.3.0-blueviolet" alt="Release v0.3.0">
</p>

---

The Watcher sits between an autonomous agent and the machine it runs on. You
describe what the agent may do in one JSON document; The Watcher evaluates the
actions that flow through it and answers **ALLOW**, **DENY**, **QUARANTINE** or
**KILL**. No model is involved in that decision. Every decision is written to a
tamper-evident Proof of Execution trace. On Linux, `--enforced` adds OS-level
containment so the boundary is enforced by the kernel rather than by cooperation.

```
Policy V1
   ↓
deterministic Watcher
   ↓
ALLOW / DENY / QUARANTINE / KILL
   ↓
Proof of Execution
   ↓
OS containment when enforced
```

No human approves individual actions, and no model is consulted. The rules are
evaluated the same way every time, and the answer is reproducible from the trace.

**Contents:** [Why it exists](#why-it-exists) · [Install](#install) ·
[Quick start](#quick-start) · [Policy V1](#policy-v1) ·
[Architecture](#architecture) · [Proof of Execution](#proof-of-execution) ·
[Security evolution](#security-evolution) · [V4](#v4) ·
[Threat model and limitations](#threat-model-and-limitations) ·
[Benchmarks](#benchmarks) · [Testing and CI](#testing-and-ci) ·
[Documentation](#documentation) · [License](#license)

## Why it exists

An agent that can run commands, read files and call APIs needs a boundary it
cannot argue with. Two failure modes motivate the design:

* **Prompt-level rules are advice.** "Do not read the secrets file" is a sentence
  the agent can be talked out of. It is not a control.
* **A model in the decision path is not deterministic.** If a model decides what
  is safe, the same action can be allowed once and denied the next time, and the
  decision cannot be audited or reproduced.

So the decision path is deliberately small and boring: a validated JSON document,
a pure function over the action, and a trace. Anything clever happens outside the
security decision, never inside it.

**Design constraints, stated as guarantees:**

* **No model in the security decision.** The policy engine is pure, synchronous
  and local. The agent is never consulted about the safety of its own action.
* **Deterministic.** The same document and the same action produce the same
  decision. A policy document has a canonical form and a stable SHA-256 digest.
* **Fail closed.** Unsupported or unenforceable configuration is refused before
  the protected process starts, never silently ignored.
* **Tamper-evident.** Decisions land in a hash-chained trace that can be verified
  after the fact.
* **Outside the agent's trust boundary.** The supervisor, the policy, the
  tripwires, the kill switch and the trace are all owned by a separate process.
* **Framework independent.** There is nothing to import into your agent. The
  Watcher wraps a command.

## Install

```bash
git clone https://github.com/ladebw/the-watcher.git
cd the-watcher
python -m pip install -e .
```

Python 3.10 or newer. Zero runtime dependencies; the standard library is enough.

## Quick start

Validate and digest a policy document without running anything:

```bash
watcher policy validate watcher.json
watcher policy digest watcher.json
```

Run an agent under that policy:

```bash
watcher run --policy watcher.json -- python agent.py
```

The policy is loaded and validated **before** the protected process is launched.
If the document is invalid, or asks for something this runtime cannot faithfully
enforce, `watcher run` exits non-zero with a located error and **no child process
is started**.

On Linux you can additionally ask the kernel to enforce containment:

```bash
watcher run --enforced -- python agent.py
watcher doctor            # what can this host actually enforce?
```

`--containment-profile` selects a named preset or a profile file for the enforced
run; the default preset is `research-strict`.

`watcher doctor` reports which protections the host can really apply. The
Watcher refuses to run in a mode it cannot honour rather than implying a
protection it does not have.

### What `--policy` does and does not do

`--policy` wires Policy V1 into The Watcher's **action evaluation path**: actions
that flow through the Watcher are decided by your rules, and every decision is
recorded. It does not, on its own, intercept arbitrary syscalls.

OS containment is a **separate Linux enforcement boundary** enabled with
`--enforced`. On Linux `--enforced` supplies the kernel-level posture
(namespaces, seccomp, Landlock, capability drop, resource limits) alongside the
cooperative policy decisions.

## Policy V1

Policy V1 is one JSON document. Path patterns are POSIX absolute paths with a
small, explicit grammar: `*` within a segment, `**` for whole segments, `?` for
one character, and literal paths otherwise. Unsupported syntax is refused rather
than treated as a literal, because a rule that silently matches nothing looks
exactly like a rule that works.

```json
{
  "version": 1,
  "filesystem": {
    "allow": ["/workspace/**"],
    "deny": ["/workspace/secret/**"]
  },
  "network": {
    "mode": "none"
  },
  "tripwires": [
    "/workspace/KILL"
  ],
  "on_violation": {
    "filesystem": "DENY",
    "tripwire": "KILL"
  }
}
```

`**` really does span segments at runtime, so `/workspace/a/b/c.txt` is inside
`/workspace/**`. DENY is evaluated before ALLOW, so a deny rule always wins over
an allow rule. See [docs/policy.md](docs/policy.md) for the complete schema,
defaults, the pattern grammar and the digest rules.

## How actions are decided

Given the policy above, the decisions are automatic:

| Action | Decision |
|---|---|
| `/workspace/file.txt` | **ALLOW** — inside `filesystem.allow`, not denied |
| `/workspace/secret/key.txt` | **DENY** — matches `filesystem.deny`, which outranks allow |
| `/workspace/KILL` | **KILL** — matches a tripwire; the existing kill switch ends the session |
| `/etc/passwd` | **DENY** — outside every `filesystem.allow` root |

There is no per-decision user interaction. The rule is evaluated, the decision is
applied, and the decision, the rule that produced it and the policy digest are
recorded in the trace.

## Architecture

```
Operator
   ↓
Policy V1 JSON
   ↓
strict validation + canonical digest
   ↓
CLI / external supervisor
   ↓
deterministic policy + tripwires + kill switch
   ↓
PoE
   ↓
protected agent
```

The policy document is validated and normalised once, producing a canonical form
and a digest. The **external supervisor** — not the agent — owns the policy, the
tripwires, the kill switch and the trace. The agent runs as a child process; a
decision that ends the session is taken outside it.

The decision vocabulary is fixed and small:

| Decision | Meaning |
|---|---|
| `ALLOW` | the action may proceed |
| `DENY` | the action is refused and recorded |
| `QUARANTINE` | the session is marked, and the next blocked action ends it |
| `KILL` | the session is terminated by the kill switch |

### Linux enforced containment

Separately from the cooperative policy decisions, `--enforced` on Linux applies
kernel-level containment:

```
Linux --enforced
   ↓
namespaces
seccomp
Landlock
capability drop
resource limits
```

These are two distinct things and this README keeps them apart on purpose:

* **Policy decisions** (ALLOW / DENY / QUARANTINE / KILL) evaluate the actions
  that flow through the Watcher. They are **cooperative**: they hold because the
  observed action is presented for evaluation, which the Watcher's action path
  and the supervisor arrange.
* **OS containment** is what the kernel enforces whether or not anyone
  cooperates: a syscall the kernel denies is denied.

## Proof of Execution

Every session produces a hash-chained trace: session start and end, every policy
decision, denials, tripwire activations, quarantines, kills and observed
signals. The trace is written by the supervisor, outside the agent's address
space, and it is sealed when the session ends.

Policy V1 decisions record structured evidence inside the existing event
metadata (the frozen top-level event schema is unchanged):

* the **policy document digest** — computed by the supervisor from the document
  it loaded, never accepted from the protected process;
* the **subsystem and rule** that produced the decision;
* the **resulting decision**;
* the **canonical subject** the rule was evaluated against.

Inspect and verify a session:

```bash
watcher status <session-id>
watcher verify trace.json
```

## Security evolution

Four milestones, each moving the trust boundary further away from the agent.

**V1 — in-process observer.** The Watcher ran inside the same process as the
agent. Useful for development, but the agent shared an address space with the
thing watching it, so the boundary was only as good as the agent's cooperation.

**V2 — external supervisor.** Policy, the trace, tripwires and the kill switch
moved into a separate supervisor process, reached over an authenticated IPC
socket. The agent could be stopped even if it never called a client library.
V2 does not provide containment: its boundaries are cooperative, because
evaluation depends on the action being presented rather than on the kernel.

**V3 — OS containment.** On Linux, declared protections became kernel-enforced:
namespaces, seccomp, Landlock path rules, capability drop, resource limits. A
denied syscall is refused by the kernel, not by advice.

**V4 — deterministic user policy and a hardened runtime.** Policy V1 became the
public configuration format: one strict JSON document, canonical digest, real
path-pattern semantics, wired into runtime decisions, with fail-closed refusal of
anything the runtime cannot faithfully enforce. V4 also hardened the V3 trust
boundaries and made IPC shutdown response-safe.

## V4

V4 is the reviewed, merged work on `main`:

* external trust-boundary hardening
* response-safe IPC shutdown
* deterministic Policy V1 JSON
* strict validation and canonical policy digest
* automatic runtime Policy V1 decisions
* filesystem ALLOW / DENY / QUARANTINE / KILL
* literal tripwire → KILL through the existing kill switch
* policy digest and evidence recorded in Proof of Execution
* fail-closed unsupported configuration
* Linux containment hardening

**Not in V4, and not claimed here:** policy layering, rate limits, an SDK or
framework adapters, cgroups, external PoE anchoring, a network-policy broker, and
automatic syscall interception by Policy V1 itself.

## Threat model and limitations

* **Policy V1 filesystem and tripwire path rules are Linux-only at runtime.**
  Policy V1 patterns are absolute POSIX paths and the format refuses drive
  letters. On Windows a rule could never match a canonical Windows path, so the
  runtime **refuses** such a document with a precise message rather than
  accepting a rule that would silently never fire.
* **Policy V1 action decisions are cooperative unless OS containment is
  enabled.** They decide the actions presented through the Watcher's action path.
  Only `--enforced` on Linux adds kernel enforcement.
* **Unsupported Policy V1 configuration fails closed.** Network modes other than
  `none`, allow/deny hostname lists, resource ceilings and wildcard tripwire
  patterns are refused before launch instead of being silently ignored.
* **`network.mode: "none"` is enforced** through the existing cooperative network
  check, which denies every target because no domain is allowed. The kernel
  no-egress posture (an empty network namespace) is supplied by Linux
  `--enforced`.
* **OS containment remains Linux-only.** On Windows, the supervisor path is
  available and containment is not.
* **Proof of Execution is tamper-evident, not externally anchored.** The chain
  detects modification; there is no external timestamp or notary in V4.
* **The Docker containment backend is experimental and unverified.**
* **The process ceiling is enforced with the runtime's own guard.** Policy V1 has
  no field for that guard, and it can escalate to KILL above the ceiling — never
  weaker than the document, but a decision the document did not author.
* **Nothing here is production-ready.** The release badge says experimental
  because that is accurate.

## Benchmarks

```bash
python benchmarks/benchmark_policy_v1.py     # policy parse, digest and match cost
python benchmarks/benchmark_v2.py            # supervisor overhead
python benchmarks/benchmark_v3.py            # containment cost
python benchmarks/benchmark_policy_v1.py --quick
```

The Policy V1 benchmark also prints an adversarial section: the worst-case
matcher cost for patterns chosen by an operator against subjects chosen by the
supervised agent, with exact comparison counts and the state bound.

## Testing and CI

```bash
python -m pytest                                    # full suite
python -m pytest -m v3                              # the Linux-only containment suite
python -m pytest tests/test_policy_v1.py            # Policy V1 document format
python -m pytest tests/test_policy_v1_runtime.py    # Policy V1 runtime wiring
python diagnostics/check_code_hygiene.py
python diagnostics/check_text_hygiene.py
python diagnostics/secret_scan.py
```

CI runs on every pull request and on `main`:

| Job | What it covers |
|---|---|
| Quality | ruff, packaging contracts, code hygiene, text hygiene, secret scan |
| Tests (ubuntu-latest, Python 3.10 / 3.12 / 3.14) | the full suite |
| Tests (windows-latest, Python 3.10 / 3.12 / 3.14) | the full suite |
| V3 containment (Linux) | requires a host that can actually contain, then runs the containment suites |

The suite is large and grows with the product, so this README deliberately does
not quote a pass count; the CI badge above is the live answer.

## Documentation

| Document | Contents |
|---|---|
| [docs/policy.md](docs/policy.md) | Policy V1: schema, defaults, pattern grammar, digest, runtime wiring, what is not enforced |
| [docs/V4_DESIGN.md](docs/V4_DESIGN.md) | the design record: decisions, threat model, phase records, measured cost |
| [diagnostics/README.md](diagnostics/README.md) | the host probes and hygiene checks |
| [LICENSE](LICENSE) | MIT |

## Project structure

```
the_watcher/     the package: watcher engine, policy, PoE, IPC, supervisor, enforcement
tests/           the test suite, including the Linux containment suites
examples/        small agents used by the demos and tests
benchmarks/      timing harnesses for policy, supervision and containment
diagnostics/     host capability probes and repository hygiene checks
public/          project artwork
docs/            policy reference and design record
```

## License

MIT. See [LICENSE](LICENSE).
