# Policy V1

The Watcher's public policy document format.

> **Status: Phase 2 — minimal policy runtime wiring.**
> This format is implemented, validated, digested, and wired into
> `watcher run --policy` through a single projection boundary. That projection
> **enforces** some fields, **refuses** others rather than applying them
> silently, and treats the rest as not applicable. What falls where is stated
> precisely in [§12](#12-runtime-wiring-phase-2) and in
> [What is not enforced yet](#what-is-not-enforced-yet). Decisions are made
> through the cooperative action API, **not** by OS-level interception.

---

## 1. Purpose

Policy V1 is a single JSON document in which a user writes down what an agent is
allowed to do. The Watcher's job is to interpret that document
**deterministically**: the same document must always mean the same thing, on
every machine, and the document's identity must be provable.

Three properties are load-bearing, and everything below exists to protect them:

1. **One document, one meaning.** No type coercion, no duplicate keys, no
   environment expansion, no platform-dependent normalisation.
2. **A stable identity.** The document digest is what gets recorded in the Proof
   of Execution, so "same meaning ⇒ same digest" has to be true.
3. **No silent acceptance.** A field or pattern the engine does not fully
   understand is a hard error, because a rule that matches nothing looks exactly
   like a rule that works.

## 2. JSON only

Policy V1 is **JSON**. It is not YAML. A hand-written YAML parser would be the
largest new attack surface this project could add, and a strict YAML *subset*
reader is a possible later addition rather than a Phase 1 deliverable. Until
then one syntax means one meaning.

The file must be **UTF-8 without a byte-order mark**, and no larger than
**1 MiB**. A BOM is refused with a message saying how to save the file
correctly; a malformed byte sequence is refused with its offset, never decoded
"as best it can".

## 3. Complete schema

```jsonc
{
  "version": 1,                       // required, exactly the integer 1

  "name": "acme-project",             // optional; [A-Za-z0-9._-]{1,64}; default "default"

  "filesystem": {                     // optional
    "allow": ["/workspace/**"],       // path patterns; empty = no allow-list
    "deny":  ["/etc/**", "/root/.ssh/**"]
  },

  "network": {                        // optional
    "mode": "none",                   // none | restricted | open; default "none"
    "allow": ["api.openai.com"],      // hostnames; only meaningful with "restricted"
    "deny":  ["metadata.google.internal"]
  },

  "process": {                        // optional
    "max_children": 8,                // integer >= 0; default 32
    "max_runtime_seconds": 600        // integer >= 1; default 3600
  },

  "resources": {                      // optional
    "memory_mb": 1024,                // integer >= 16; omit = not configured
    "cpu_seconds": 600                // integer >= 1;  omit = not configured
  },

  "tripwires": [                      // optional; path patterns
    "/var/run/docker.sock",
    "/root/.ssh/id_rsa"
  ],

  "on_violation": {                   // optional
    "filesystem": "DENY",             // DENY | QUARANTINE | KILL
    "network":    "DENY",
    "process":    "DENY",
    "resources":  "QUARANTINE",
    "tripwire":   "KILL"              // only KILL is accepted
  }
}
```

### 3.1 Defaults

Every section is optional. A field with a declared default is **materialised**
in the canonical form, so omitting a section and writing its defaults out are
the same document with the same digest. `resources.memory_mb` and
`resources.cpu_seconds` are the exception: they are *not configured* by default
and are **omitted** when unset, so the canonical form never contains a `null`.

### 3.2 Rules that are not obvious

- **Unknown keys are refused at every level**, with a near-miss suggestion:
  `filesystem.alow: unknown field; did you mean 'allow'?`
- **Duplicate keys are refused**, at every level. Python's `json` module keeps
  the *last* duplicate and says nothing, so
  `{"filesystem": {...}, "filesystem": {...}}` would silently discard a rule
  set. That is not acceptable in a security policy.
- **`NaN`, `Infinity` and `-Infinity` are refused.** They are not JSON, and they
  have no deterministic representation in the canonical encoder.
- **`null` is refused wherever it appears.** Omit the field instead.
- **No coercion, ever.** `"32"` is not `32`; `1.0` is not `1`; `true` is not `1`.
- **`on_violation.tripwire` may only be `KILL`.** A tripwire's purpose is to end
  the session; `DENY` or `QUARANTINE` cannot be honoured, so they are refused
  rather than recorded as a posture nothing implements.
- **`ALLOW` is refused as a violation decision** for every class. A class that
  decides nothing is the same as omitting it, and the spelling invites a
  document that quietly disables a control.
- **`network.allow` holds hostnames, not addresses.** A CIDR or IP literal is
  refused with a pointer at `ContainmentProfile.allowed_networks`, which is
  where address-level rules live. One field must not mean two things.
- **There is no `resources.pids`.** The process ceiling is
  `process.max_children`; a second name for one ceiling would give it two
  meanings. The error says so.

### 3.3 Fields that exist elsewhere in the project

Some names belong to another subsystem. The parser points at the right place
rather than shrugging:

| Written | Belongs to | Error |
|---|---|---|
| `resources.pids` | `process.max_children` | names the correct field |
| `process.max_processes` | `process.max_children` | names the correct field |
| `filesystem.allowed_paths` | `filesystem.allow` | names the correct field |
| `network.allowed_networks` | containment profile (CIDRs) | names the profile |
| `network.restrict_network` | `network.mode` | names the correct field |
| `tripwires: [{...}]` | tripwire registry (object form) | Policy V1 takes paths |

## 4. Path matching grammar

This is the security-critical part, and the grammar is deliberately tiny.

| Pattern | Matches |
|---|---|
| `/a/b` | `/a/b` **and every descendant** (existing V3 implicit-subtree meaning, preserved) |
| `/a/**` | exactly the same set as `/a`: the prefix and every descendant |
| `/a/*` | `/a` plus exactly **one** further segment, never deeper |
| `/a/*.conf` | one segment under `/a` ending in `.conf` |
| `/a/?` | one segment under `/a` of exactly one character |
| `/a/**/b` | `/a/b`, `/a/x/b`, `/a/x/y/b` — `**` spans zero or more segments |

Everything else is a literal character.

- `*` matches within one segment and **never crosses a `/`**.
- `**` is only meaningful as a **whole segment**; `/a**b` is refused.
- Unsupported syntax — `[`, `]`, `{`, `}`, `!`, `\` — is **refused**, not
  treated as a literal. This is the specific defect the V3 audit found: `**` was
  not implemented at all, so `deny: ["/etc/**"]` matched *nothing* and looked
  exactly like a working rule.
- A pattern with a wildcard does **not** imply a subtree. `/a/*` matches one
  level. Write `/a/**` for a subtree.
- A bare literal path **does** imply a subtree, because that is what V3 already
  meant by `forbidden_paths: ["/etc"]`, and changing it would weaken existing
  policies.

### 4.1 Canonicalisation

Applied to patterns, and to subject paths when matching:

| Input | Canonical | Why |
|---|---|---|
| `/etc/` | `/etc` | a trailing separator never changes meaning |
| `/etc//passwd` | `/etc/passwd` | duplicate separators collapse |
| `/etc/./passwd` | `/etc/passwd` | `.` is lexically a no-op |
| `//etc` | `/etc` | leading separators collapse |

### 4.2 What is refused, and why

| Rejected | Reason |
|---|---|
| `/workspace/../etc` | collapsing `..` would silently change the rule (`/etc`), and resolving it correctly needs the filesystem, which matching must never touch |
| `etc/passwd` | patterns must be absolute |
| `~/.ssh/**`, `$HOME/.ssh`, `%USERPROFILE%` | expanding these makes one document mean different things on different machines, which breaks the digest |
| `C:/etc`, `/etc\passwd` | drive letters and backslashes give a document two meanings depending on platform |
| `[abc]`, `{a,b}`, `!(x)`, `a**b` | unsupported syntax must be an error, never a literal |
| a lone surrogate, e.g. `"/tmp/\ud800/**"` | a surrogate is not valid Unicode text and cannot appear in a UTF-8 path, so the rule could never match anything. Only a JSON `\uD800`-style escape can produce one; a rule that silently matches nothing is refused everywhere else in this format, and it is refused here for the same reason |

**Case is not folded.** Matching is case-sensitive on every platform, and the
matcher never consults the filesystem's case sensitivity. The digest of a
document is therefore identical on Windows and Linux for the same bytes, which
is what makes cross-platform policy comparison meaningful.

**Matching never touches the filesystem.** No symlink resolution, no `stat`, no
existence check. A pattern is a rule about path *strings*; deciding what a path
resolves to is a separate question, and one this layer does not answer.

**Unicode normalisation is not applied.** `café` written in NFC and `café`
written in NFD are two different patterns, and each matches only its own
spelling. Normalising would silently rewrite an operator's rule, and
normalisation is itself a way to make two distinct byte strings collide. The
cost is real and worth stating plainly: a rule copied out of an editor that
writes NFD will not match a path encoded as NFC. Where a rule must cover both
spellings, write both, or let `*` / `?` span the difference.

### 4.3 Cost

Matching runs in the trusted path, so its cost is a security property. The
subject is chosen by the agent being supervised and the pattern by the operator,
so a matcher whose cost is superlinear in the subject lets the watched party
spend the watcher's CPU.

Every input is bounded: patterns and subjects are each capped at 4096
characters and 256 segments (§3.2), and anything longer is refused rather than
truncated. Within those caps the cost is bounded and small:

| Shape | Cost |
|---|---|
| literal path | one string comparison per segment |
| a `*`-anchored block | one comparison each |
| a literal block that must be located | one C-level substring search |
| a `?` block that must be located | one bit-parallel scan, per-character work in C |
| worst adversarial shape measured at the caps | ~0.6 ms |

The segment level (`**`) is bounded separately and is checked rather than
assumed. With `P` pattern segments and `T` subject segments, `_segments_match`
visits **at most `(P + 1) × (T + 1)` states** — 257 × 257 = 66,049 under the
caps — and it **never re-enters a state**: every walk that follows a backtrack
runs along a fresh diagonal. The bound follows from a potential-function
argument recorded on the function (`Φ = (T − mark)(P + 1) + (P − pi)`, which every
branch lowers by at least one), and it is verified independently: an exhaustive
sweep of small inputs plus a randomised search at the caps, both finding zero
revisits, with a test asserting the bound.

Note carefully what the bound is **not**. It is **not `P × T`**: a lone `**`
against 77 segments visits **78** states, because the loop enters once to read the
`**` and then once per following position. `78 > 77`, so `P × T` is false as an
absolute bound even though the cost remains **`O(P × T)`** asymptotically — since
`(P + 1)(T + 1) = PT + P + T + 1`. A test pins that counterexample, and the
benchmark prints the `(P + 1)(T + 1)` bound rather than the naive one.

Extra memory is bounded and small: constant at the segment level, and
proportional to the pattern at the character level (the split into `*`-free
blocks and the bit-parallel masks). **Nothing is allocated in proportion to
pattern × subject.** Both matchers are iterative, so a deep or wide input cannot
exhaust the stack either.

The measured worst case for a `**`-heavy near miss at the caps is ~23 ms per
match attempt, and reaching it needs a hand-written pattern carrying 128 `**`
segments and 128 `?` segments. A realistic policy costs microseconds. Note the
asymmetry: the *pattern* is operator-authored and trusted, while the *subject* is
chosen by the supervised agent — and the subject cannot push the work past the
pattern's own `(P + 1) × (T + 1)` bound.

The absolute figure matters less than what it replaced. An earlier version of
this matcher kept a single backtrack point and re-scanned the whole pattern tail
once per subject character, so its cost grew with pattern × subject:
`"/" + "*" + "?" * 2040` against a 4095-character subject cost **1.7 seconds of
CPU for one match attempt**, and an agent choosing its own paths could repeat
that at will. The same input now costs about 50 µs. A test asserts a wall-clock
ceiling on every adversarial shape, so the quadratic form cannot return
unnoticed.

## 5. Normalization rules

The canonical form is what the digest is taken over. Producing it:

1. Every section key is always present.
2. Fields with a declared default are materialised.
3. `resources` keys are omitted when not configured.
4. Rule lists (`filesystem.allow`, `filesystem.deny`, `tripwires`) are
   **de-duplicated and sorted by Unicode code point**. Their order carries no
   meaning: Policy V1 has no first-match-wins rule, and deny/is-restricted wins
   over allow. (V3's engine evaluates an *ordered* rule list internally; that
   ordering is V3's, not the document's, and Phase 2 is where the projection
   must be shown to preserve these semantics.)
5. `network.allow` / `network.deny` are lower-cased (DNS is case-insensitive)
   and sorted.
6. Nothing else is reordered, re-cased or reformatted.

Sorting is deliberately by Unicode code point, never by locale, and the encoder
sets `ensure_ascii=True`, so the same logical value produces the same bytes on
every platform and Python version.

## 6. Digest

```
document_digest = SHA256("watcher-policy-document/1" + 0x00 + canonical_json(normalized))
```

- Built on the same canonical encoder the Proof of Execution uses
  (`the_watcher.poe.canonical`), so **any change that could change behaviour
  changes the digest**, and vice versa.
- **Domain-separated.** A policy digest can never collide with a PoE event hash
  or a bare canonical-JSON digest.
- Invariant under: JSON key order, whitespace and formatting, rule order,
  hostname case, and equivalent path spellings.
- Changes on: any rule, any ceiling, any violation decision, the name.

```console
$ watcher policy digest watcher.json
5920fb023ea642059c65f49fa8062762c0e156279a603cd1754dbdd671ae1ac5
```

`watcher-policy-resolved/1` is **reserved** for Phase 2 (layered policies). Phase
1 does not produce it, and does not copy the document digest into that namespace:
a resolved-policy digest must describe the *merged* policy, and returning the
document digest under that name would misstate which policy was in force.

## 7. Validation errors

Errors are structured, not prose. Every issue carries a **path**, a
**machine-readable code**, and a message:

```
filesystem.alow: unknown field; did you mean 'allow'?
filesystem: duplicate key; the later value would silently replace the earlier one
process.max_children: expected an integer, got string; Policy V1 never coerces a value into the expected type
network.allow[0]: '10.0.0.0/8' looks like an address, CIDR or host:port. Policy V1 'network.allow' takes hostnames; ...
on_violation.tripwire: a tripwire can only be KILL; 'DENY' is refused rather than recorded, ...
```

Every issue in the document is reported, not just the first, so a review is one
pass rather than a fix-and-retry loop. Error text quotes the offending *field*,
never the whole document, so a policy naming sensitive paths does not leak them
into a log.

```python
from the_watcher.exceptions import PolicyValidationError

try:
    policy = load_policy("watcher.json")
except PolicyValidationError as exc:
    for issue in exc.issues:
        print(issue.path, issue.code, issue.message)
```

## 8. Public Python API

```python
from the_watcher.policy_v1 import load_policy, loads_policy, parse_policy, PolicyV1

policy = load_policy("watcher.json")     # from a file
policy = loads_policy(text)              # from a string
policy = parse_policy({"version": 1})    # from an already-decoded mapping

policy.version                            # 1
policy.name                               # "default"
policy.filesystem.allow                   # tuple[PathPattern, ...]
policy.filesystem.deny[0].pattern         # "/etc/**"
policy.filesystem.deny[0].matches("/etc/passwd")   # True
policy.network.mode                       # "none"
policy.process.max_children               # 32
policy.resources.memory_mb                # None when not configured
policy.tripwires                          # tuple[PathPattern, ...]
policy.on_violation["tripwire"]           # "KILL"
policy.normalized()                       # the canonical form (read-only)
policy.document_digest                    # the domain-separated SHA-256
policy.to_dict()                          # a plain JSON-serialisable copy
```

The parsed policy is **immutable**: frozen dataclasses, tuples, and read-only
mappings. Mutating the caller's source mapping after parsing does not change the
policy or its digest.

`PathPattern.matches(path)` answers a question about *patterns*. It is not a
policy decision, and it raises `PolicyValidationError` on a subject it cannot
parse (relative, backslash, `..`) rather than answering "no match" to a question
it did not understand.

## 9. CLI

```console
$ watcher policy validate watcher.json
VALID Policy V1

$ watcher policy validate broken.json
filesystem.alow: unknown field; did you mean 'allow'?
$ echo $?
2

$ watcher policy digest watcher.json
5920fb023ea642059c65f49fa8062762c0e156279a603cd1754dbdd671ae1ac5

$ watcher policy digest watcher.json --json
{
  "document_digest": "5920fb023ea642059c65f49fa8062762c0e156279a603cd1754dbdd671ae1ac5",
  "name": "default",
  "version": 1
}
```

`validate` prints `VALID Policy V1` on success and one located line per problem
on stderr otherwise; `digest` prints only the digest by default so it can be
piped. Exit code `0` on success, `2` on any validation or parse failure.

## 10. What is not enforced yet

As of Phase 2 the format is wired into `watcher run --policy` (§12), but not
every field is enforceable there. A field the runtime cannot faithfully apply is
**refused** rather than silently ignored, so no control is absent without a loud
error; the remaining fields stay document configuration. A V3 policy file is
unaffected and still loads through the V3 loader.

| Section | Status with `watcher run --policy` | Not enforced yet |
|---|---|---|
| `filesystem` | **enforced** for a Policy V1 document: `allow`/`deny` are evaluated with Policy V1 pattern semantics, deny before allow. Refused on Windows, where an absolute POSIX pattern cannot match a `C:/...` subject | OS-level interception; containment remains the enforcement backends' job |
| `network` | `mode: "none"` (the default) is enforced as **no network access**: the projection sets `restrict_network = True` with an empty allow-list, so the cooperative domain check denies every target. `restricted`/`open` and non-empty allow/deny lists are refused | the broker, Phase 8 |
| `process` | **enforced** for a Policy V1 document: `max_runtime_seconds` becomes the supervisor session timeout the kill switch enforces, and `max_children` is projected onto the runtime process-tree ceiling | `RLIMIT_NPROC` / `pid_max` projection, Phase 2+ |
| `resources` | document only; the Phase 2 projection **refuses** a configured ceiling | rlimits now, cgroups in Phase 7; ceilings remain a containment-profile concern |
| `tripwires` | **enforced** for a Policy V1 document when the pattern is a literal path; a wildcard pattern is refused because the registry matches literal paths only | nothing further planned in this phase |
| `on_violation` | **enforced** for `filesystem` and `tripwire`; document only for `network`, `process` and `resources`, whose decisions the projection refuses when changed from their documented defaults | decision mapping for those subsystems waits on the subsystems themselves |

`the_watcher.policy_v1.ENFORCED_IN_PHASE_1` carries the Phase 1 per-section
status in code and a test still asserts it says "no runtime enforcement"; that
constant describes Phase 1 and is deliberately unchanged. What the runtime
enforces now comes from the projection in `the_watcher/policy_v1_runtime.py`,
and an unenforceable document is refused there rather than ignored here.

`the_watcher.enforcement.declared` remains the authority on what a containment
backend actually enforces for a given profile.

## 11. Layering (future)

Phase 2 wires the document to the runtime (§12) and **does not** add layering.
A later phase will add `Watcher baseline → Organization → Project → Session` with
a deterministic merge that can only ever *add* restriction:

```
DENY > ALLOW
KILL tripwire > ordinary rules
hard ceilings cannot be increased downstream
restricted network cannot become open downstream
resource ceilings may only become stricter
mandatory rules cannot be disabled
```

The result of that merge is what `watcher-policy-resolved/1` will digest. See
`docs/V4_DESIGN.md` §5 for the merge lattice. Phase 1 defines only the *document*
— one layer, as authored.

## 12. Runtime wiring (Phase 2)

Phase 2 connects the Phase 1 document to the running supervisor through exactly
one new module, `the_watcher/policy_v1_runtime.py`. That module is the only
boundary between the document format and the runtime: `the_watcher/policy_v1.py`
stays a pure document model with no runtime authority, and the V3/V2 runtime
keeps owning decisions, tripwires, the kill switch and the trace.

```console
$ watcher run --policy watcher.json -- python agent.py
```

### 12.1 Format detection

`watcher run --policy FILE` decides from the document itself which loader to use:

- a document with a top-level `"version"` key is **Policy V1**;
- anything else keeps the **existing V3** path it has today.

The two cannot be confused in either direction. Policy V1 *requires* `version`,
and the V3 schema has no `version` field and rejects unknown keys
(`Policy.from_dict`), so a document written for one format cannot load as the
other. The detection parse is only a discriminator, not a validation: the chosen
loader re-parses the same text strictly, so duplicate keys, non-finite numbers
and every other refusal still come from the strict loader. A file that is not
JSON at all falls through to the V3 loader, which reports the syntax error
exactly as it does now.

### 12.2 The projection is deterministic

The projection is a deterministic function of the **canonical** document. There
is no clock, no environment lookup and no filesystem access in it. Because the
canonical form is what the digest is taken over, two documents with the same
digest produce the same runtime configuration.

The classification is derived from field *values*, never from whether a key was
written. Policy V1 materialises defaults, so `{"network": {"mode": "none"}}` and
omitting `network` normalise to the same bytes and therefore receive the same
treatment.

### 12.3 Per-field classification

Every Policy V1 field is classified, and the classification is enforced rather
than documented and hoped for. `ENFORCED` means the runtime does the thing the
document says. `NOT APPLICABLE` means the field holds its documented default, so
the author configured nothing and there is nothing to enforce. `REFUSED` means
the document asks for something this runtime cannot faithfully do — and a
refusal is an error, never a silent no-op.

| Field | Classification | Runtime effect |
|---|---|---|
| `version` | ENFORCED | the version is validated as part of loading |
| `name` | ENFORCED (recorded) | recorded as the runtime policy name |
| `filesystem.allow` | ENFORCED when non-empty; NOT APPLICABLE when empty | Policy V1 pattern semantics at runtime |
| `filesystem.deny` | ENFORCED when non-empty; NOT APPLICABLE when empty | Policy V1 pattern semantics, evaluated before allow |
| `on_violation.filesystem` | ENFORCED | DENY / QUARANTINE / KILL all map to existing runtime decisions |
| `on_violation.tripwire` | ENFORCED | Policy V1 permits only KILL, which the existing kill switch applies |
| `process.max_runtime_seconds` | ENFORCED | applied as the supervisor session timeout enforced by the kill switch |
| `process.max_children` | ENFORCED when set; NOT APPLICABLE at the default 32 | projected onto the runtime process-tree ceiling; conservative, because total <= N implies children <= N |
| `network.mode` = `"none"` (the default) | ENFORCED | **`none` means no network access**, not "no network policy": it is projected as `restrict_network = True` with an empty allow-list, so the existing domain check denies every target. The kernel-enforced half of that mapping — the empty network namespace — is the containment posture and needs `--enforced` on Linux; without it the denial is cooperative, not OS interception |
| `network.mode` = `"restricted"` or `"open"` | REFUSED | there is no network interception in this runtime; the broker is Phase 8 |
| `network.allow`, `network.deny` | REFUSED when non-empty | a broker is required to honour a hostname allow/deny list; the broker is Phase 8 |
| `resources.memory_mb`, `resources.cpu_seconds` | REFUSED when set | resource ceilings are a containment-profile concern, not a policy-document one |
| `on_violation.network`, `on_violation.process`, `on_violation.resources` | REFUSED when changed from their documented defaults | no rule of that subsystem is enforceable here, so the decision could never be applied faithfully |
| `tripwires` | ENFORCED for literal paths; REFUSED for a pattern using `*`, `**` or `?` | the tripwire registry matches literal paths only, so a wildcard would be registered as a literal that never fires |
| anything else at its documented default (or absent) | NOT APPLICABLE | the author configured nothing |

`filesystem` and `tripwires` are ENFORCED only where an absolute POSIX pattern
can match the action path. On Windows the projection refuses both rather than
accepting a rule that cannot fire (§12.8).

**One runtime guard is not configurable from the document.** `process.max_children`
is projected onto the runtime process-tree ceiling, and the runtime additionally
KILLs when the tree exceeds that ceiling by its own multiplier (3). Policy V1 has
no field for that guard, so a document declaring
`on_violation.process = "DENY"` can still reach KILL. It only ever escalates
relative to the document — never weaker — but it is a decision the document did
not author, and the degenerate case is worth knowing: with
`process.max_children = 0` the guard's hard limit is `0 × 3`, so **any** child
process reaches KILL rather than DENY.

### 12.4 Fail closed

Any REFUSED field makes `watcher run` fail. The document is loaded, validated
and projected **before** the protected process is launched, so a refusal exits
`2` with a located error and **no child is started**. A document that asks for a
control this runtime cannot apply never runs half-protected, and a control is
never silently missing.

### 12.5 Precedence and one canonical subject

- **DENY is evaluated before ALLOW**, always. A path that matches a deny rule is
  denied even when it also matches an allow rule.
- **A configured allow-list is a default-deny** for paths outside it. This is
  the one behaviour Policy V1 inherits unchanged from V3.
- **When no allow-list is configured, an absent allow-list restricts nothing.**
  That is the documented V3 behaviour, preserved rather than reinterpreted.
- **One canonical subject per action.** The action path is canonicalised once
  using the runtime's existing canonicalisation (relative paths resolve against
  `--workspace`) and the result is reused for every rule. DENY and ALLOW are then
  evaluated against that single string, so two rules cannot disagree about which
  path they decided on.

### 12.6 Interaction with CLI flags

`--allow-path`, `--forbid-path`, `--allow-domain`, `--forbid-domain` and
`--max-processes` configure the **V3** policy document. A Policy V1 document
defines those rules itself, so combining these flags with a Policy V1 document
is refused rather than silently resolved in one direction or the other. An
explicit `--timeout` is still accepted: the stricter of it and
`process.max_runtime_seconds` wins.

### 12.7 Proof of Execution

Every Policy V1 decision records, inside the existing event metadata (the frozen
top-level event schema is unchanged), a `policy_evidence` object:

| Key | Value |
|---|---|
| `policy_format` | `watcher-policy/1` |
| `policy_document_digest` | the supervisor-computed digest from Phase 1 |
| `policy_subsystem` | the subsystem that produced the decision |
| `policy_rule` | the rule that fired, e.g. `policy_v1:filesystem.deny[2]` |
| `canonical_subject` | the one canonical action path the rule was evaluated against |

The digest is computed by the supervisor, and the evidence is merged into the
metadata last, so a workload-supplied value of the same name cannot displace it.

### 12.8 Platform limitation (Windows)

Policy V1 patterns are absolute POSIX paths, and the format refuses drive
letters on purpose, so that one document means one thing everywhere. A Windows
action path canonicalises to `C:/...`, which no absolute POSIX pattern can ever
equal. On Windows a non-empty filesystem rule or tripwire pattern would
therefore match nothing while looking exactly like a working rule, so the
projection **refuses** such a document with a precise message instead of
accepting it. On Windows, only documents with no filesystem rules and no
tripwire patterns project successfully.

### 12.9 What this is, and is not

Decisions are produced through the existing `PoEWatcher.evaluate` cooperative
action API. This is **not OS-level interception**: the runtime decides when the
workload asks it to decide, and containing a workload that does not ask remains
the job of the enforcement backends (`the_watcher.enforcement.declared` remains
their authority on what a backend actually enforces).

The old V3 policy format is unchanged. A V3 policy file still loads through the
V3 loader, and `watcher run` without `--policy` behaves exactly as before.
