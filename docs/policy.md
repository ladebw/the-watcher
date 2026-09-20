# Policy V1

The Watcher's public policy document format.

> **Status: Phase 1 — schema, normalisation and digest.**
> This format is implemented, validated and digested. **Nothing in it is
> enforced at runtime yet**, and it is deliberately **not** wired into
> `watcher run`. Do not deploy it as a control; see
> [What is not enforced yet](#what-is-not-enforced-yet).

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

**No Policy V1 field is enforced at runtime, and the format is not wired into
`watcher run`.** `watcher run --policy` still loads the existing V3 policy JSON;
feeding it a Policy V1 document fails loudly.

| Section | Phase 1 status | Planned |
|---|---|---|
| `filesystem` | document only | Landlock allow-list + evaluator, Phase 2+ |
| `network` | document only | refused at runtime today; broker in Phase 8 |
| `process` | document only | `RLIMIT_NPROC` / `pid_max` projection, Phase 2+ |
| `resources` | document only | rlimits now, cgroups in Phase 7 |
| `tripwires` | document only | tripwire registry projection, Phase 2 |
| `on_violation` | document only | decision mapping, Phase 2 |

`the_watcher.policy_v1.ENFORCED_IN_PHASE_1` carries this table in code, and a
test asserts it still says "no runtime enforcement", so the documentation cannot
drift ahead of the implementation.

`the_watcher.enforcement.declared` remains the authority on what a containment
backend actually enforces for a given profile.

## 11. Layering (future)

Phase 2 will add `Watcher baseline → Organization → Project → Session` with a
deterministic merge that can only ever *add* restriction:

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
