"""Command line interface.

V2 is the default. ``watcher run`` starts an external supervisor, binds a
local IPC endpoint, launches the protected command as a *child* of the
supervisor, and records a tamper-evident trace outside the sandbox.

    watcher run -- python agent.py
    watcher run --trace-out trace.json --timeout 30 --fail-closed -- python agent.py
    watcher status <session-id>
    watcher verify traces/session.json
    watcher demo

``--inline`` selects the V1 behaviour, where the Watcher runs inside the same
process. That mode is kept for embedding and comparison, but it is not a
control plane: policy, trace and kill switch all live with the watched code.

Exit codes: the protected process's own code, 124 when the session timed out
in ``--inline`` mode, or 137 whenever the kill switch was engaged.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
from typing import Any, Sequence

from . import __version__
from .exceptions import PolicyError
from .poe import TraceVerifier
from .watcher import Policy, PoEWatcher

KILLED_EXIT_CODE = 137
TIMEOUT_EXIT_CODE = 124


@contextlib.contextmanager
def supervisor_signal_handlers(daemon: Any):
    """Route ``SIGINT``/``SIGTERM`` into a controlled supervisor shutdown.

    The handler does the minimum a signal handler may safely do: it asks the
    daemon to shut down. The daemon's ordinary supervision loop then performs
    the real work - the recorded kill, the containment teardown, the seal - on
    the normal code path, under the normal lock. Asynchronous cleanup inside the
    handler frame is deliberately avoided.

    Handlers are installed only in the main thread of the process that owns the
    daemon, because ``signal.signal`` is not permitted anywhere else; every
    failure to install is ignored rather than fatal, so behaviour on platforms
    with partial signal support (notably Windows, where ``SIGTERM`` is not
    delivered by ``TerminateProcess``) is unchanged.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def _handler(signum: int, _frame: Any) -> None:
        try:
            name = signal.Signals(signum).name
        except ValueError:  # pragma: no cover - platform specific
            name = str(signum)
        daemon.request_shutdown(f"SIGNAL:{name}")

    previous: dict[int, Any] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[signum] = signal.signal(signum, _handler)
        except (ValueError, OSError, AttributeError):  # pragma: no cover
            continue

    try:
        yield
    finally:
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):  # pragma: no cover
                continue


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="watcher",
        description=(
            "Runtime observation, Proof of Execution and emergency control "
            "for autonomous AI systems."
        ),
    )
    parser.add_argument("--version", action="version", version=f"watcher {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run",
        help="run a command under the Watcher",
        description="Run a command under the Watcher: policy, tripwires, PoE trace.",
    )
    run.add_argument("--policy", metavar="FILE", help="policy file: a Policy V1 JSON document, or an existing V3 policy")
    run.add_argument(
        "--trace-out",
        metavar="FILE",
        help="write a sealed copy of the trace here (supervisor-side export)",
    )
    run.add_argument(
        "--workspace",
        metavar="DIR",
        default=os.getcwd(),
        help="workspace root used to resolve relative paths (default: cwd)",
    )
    run.add_argument(
        "--allow-path",
        action="append",
        default=[],
        metavar="PATH",
        help="allow filesystem access under PATH (repeatable)",
    )
    run.add_argument(
        "--forbid-path",
        action="append",
        default=[],
        metavar="PATH",
        help="forbid filesystem access under PATH (repeatable)",
    )
    run.add_argument(
        "--allow-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="allow network access to DOMAIN; enables a network allow-list",
    )
    run.add_argument(
        "--forbid-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="forbid network access to DOMAIN (repeatable)",
    )
    run.add_argument(
        "--max-processes",
        type=int,
        default=None,
        metavar="N",
        help="maximum number of processes in the protected tree",
    )
    run.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="end the session after SECONDS (enforced by the kill switch in V2)",
    )
    run.add_argument(
        "-q", "--quiet", action="store_true", help="only print the trace location"
    )

    # -- V2 supervisor controls -----------------------------------------
    run.add_argument(
        "--storage-root",
        metavar="DIR",
        default=None,
        help="where the authoritative trace is stored (default: application data)",
    )
    run.add_argument(
        "--ipc-timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="how long a client waits for a Watcher answer (default: 5)",
    )
    run.add_argument(
        "--fail-mode",
        choices=("fail_closed", "fail_open"),
        default="fail_closed",
        help="client behaviour when the Watcher is unreachable (default: fail_closed)",
    )
    run.add_argument(
        "--fail-closed",
        dest="fail_mode",
        action="store_const",
        const="fail_closed",
        help="shorthand for --fail-mode fail_closed",
    )
    run.add_argument(
        "--heartbeat-interval",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="how often the protected client reports liveness (default: 5)",
    )
    run.add_argument(
        "--heartbeat-timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="how long a silent client may go before it is flagged (default: 30)",
    )
    run.add_argument(
        "--heartbeat-action",
        choices=("record", "quarantine", "kill"),
        default="record",
        help="response to a lost heartbeat (default: record only)",
    )
    run.add_argument(
        "--no-heartbeat",
        dest="heartbeat_interval",
        action="store_const",
        const=0.0,
        help="disable the heartbeat expectation",
    )
    run.add_argument(
        "--ipc-lost-action",
        choices=("record", "quarantine", "kill"),
        default="record",
        help="response to losing the authenticated control channel (default: record)",
    )
    run.add_argument(
        "--child-env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "extra environment variable for the protected process (repeatable); "
            "the session's own WATCHER_* connection variables always win"
        ),
    )
    run.add_argument(
        "--inline",
        action="store_true",
        help="run the V1 in-process Watcher instead of the external supervisor",
    )

    # -- V3 OS-enforced containment --------------------------------------
    run.add_argument(
        "--enforced",
        action="store_true",
        help=(
            "require OS-enforced containment: DENY becomes an operating-system "
            "refusal rather than a message from the Watcher"
        ),
    )
    run.add_argument(
        "--containment-profile",
        metavar="NAME|FILE",
        default=None,
        help=(
            "containment profile preset (research-strict, research-net, dev) "
            "or a JSON profile file (default: research-strict)"
        ),
    )
    run.add_argument(
        "--enforcement-backend",
        choices=("auto", "namespaces", "docker"),
        default=None,
        help="containment backend; an unavailable explicit backend is an error",
    )
    run.add_argument(
        "--network",
        choices=("none", "restricted", "open"),
        default=None,
        help="network policy inside the sandbox (default: none)",
    )
    run.add_argument(
        "--read-only-root",
        dest="read_only_root",
        action="store_true",
        default=None,
        help="remount the container root filesystem read-only (default: on)",
    )
    run.add_argument(
        "--writable-root",
        dest="read_only_root",
        action="store_false",
        help="allow writes outside the workspace (weakens containment)",
    )
    run.add_argument(
        "--memory",
        type=int,
        default=None,
        metavar="MB",
        help="memory ceiling for the sandbox",
    )
    run.add_argument(
        "--cpus",
        type=float,
        default=None,
        metavar="N",
        help="cpu ceiling for the sandbox",
    )
    run.add_argument(
        "--pids",
        type=int,
        default=None,
        metavar="N",
        help="maximum number of processes inside the sandbox",
    )
    run.add_argument(
        "--enforcement-runtime-root",
        metavar="DIR",
        default=None,
        help="where the backend keeps guard copies and reports (default: a temp dir)",
    )
    run.add_argument(
        "--allow-reduced-protection",
        action="store_true",
        help=(
            "accept running without a requested resource control the backend "
            "cannot enforce (e.g. --cpus on a backend with no cgroup quota). "
            "Without this, such a request is refused before launch. The waiver "
            "is recorded in the Proof of Execution."
        ),
    )
    run.add_argument(
        "protected_command",
        nargs=argparse.REMAINDER,
        metavar="-- COMMAND [ARGS...]",
        help="command to run, introduced by --",
    )

    status = subparsers.add_parser(
        "status",
        help="show the stored record for a finished session",
        description="Read the authoritative metadata and trace for a session.",
    )
    status.add_argument("session_id", metavar="SESSION-ID")
    status.add_argument("--storage-root", metavar="DIR", default=None)

    verify = subparsers.add_parser(
        "verify", help="verify a trace file", description="Verify a PoE trace file."
    )
    verify.add_argument("trace", metavar="TRACE.json", help="trace file to verify")
    verify.add_argument(
        "-q", "--quiet", action="store_true", help="exit code only, no output"
    )

    demo = subparsers.add_parser(
        "demo",
        help="run a scripted demonstration",
        description="Run a self-contained demonstration of policy, tripwires and kill switch.",
    )
    demo.add_argument(
        "--v2",
        action="store_true",
        help="run the external-supervisor (V2) demonstration instead of the in-process one",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="report which containment protections this host can enforce",
        description=(
            "Probe the host for namespaces, seccomp, Landlock, capabilities, "
            "cgroups and container runtimes, and state plainly what V3 can and "
            "cannot enforce here."
        ),
    )
    doctor.add_argument(
        "--json", action="store_true", help="emit the raw capability report"
    )
    doctor.add_argument(
        "--containment-profile",
        metavar="NAME|FILE",
        default=None,
        help="also check a specific profile against this host",
    )
    doctor.add_argument(
        "--workspace",
        metavar="DIR",
        default=os.getcwd(),
        help="workspace to test Landlock reach against (default: cwd)",
    )

    # -- policy ----------------------------------------------------------
    # Policy V1 is a document format, not a runtime control. These subcommands
    # validate and digest a document; nothing here is wired into `watcher run`,
    # because no Policy V1 field is enforced yet and implying otherwise is the
    # one thing this project must never do.
    policy = subparsers.add_parser(
        "policy",
        help="validate or digest a Policy V1 document",
        description=(
            "Work with Policy V1 documents (JSON). Validation is strict: "
            "unknown fields, duplicate keys, non-finite numbers and type "
            "mismatches are refused rather than coerced."
        ),
    )
    policy_commands = policy.add_subparsers(
        dest="policy_command", required=True, metavar="{validate,digest}"
    )

    policy_validate = policy_commands.add_parser(
        "validate",
        help="validate a Policy V1 document",
        description="Report every problem in a Policy V1 document, or VALID.",
    )
    policy_validate.add_argument("file", metavar="FILE")

    policy_digest = policy_commands.add_parser(
        "digest",
        help="print the canonical digest of a Policy V1 document",
        description=(
            "Print the domain-separated SHA-256 of the canonical normalised "
            "document. Prints only the digest by default so it can be scripted."
        ),
    )
    policy_digest.add_argument("file", metavar="FILE")
    policy_digest.add_argument(
        "--json", action="store_true", help="emit a JSON object instead of the bare digest"
    )
    return parser


class _PolicySource:
    """The policy in force, plus what a Policy V1 document brings alongside it."""

    def __init__(
        self,
        policy: Policy,
        tripwires=None,
        projection=None,
        session_timeout=None,
    ) -> None:
        self.policy = policy
        self.tripwires = tripwires
        self.projection = projection
        self.session_timeout = session_timeout


#: Flags that configure the *V3* policy document. A Policy V1 document defines
#: these itself, so the combination is refused rather than silently resolved in
#: one direction or the other.
_V3_SHAPING_FLAGS = (
    ("allow_path", "--allow-path"),
    ("forbid_path", "--forbid-path"),
    ("allow_domain", "--allow-domain"),
    ("forbid_domain", "--forbid-domain"),
    ("max_processes", "--max-processes"),
)


def _apply_v3_overrides(args: argparse.Namespace, policy: Policy) -> None:
    """Explicit CLI flags always win over the V3 policy file."""
    if args.allow_path:
        policy.allowed_paths = tuple(args.allow_path)
    if args.forbid_path:
        policy.forbidden_paths = tuple(policy.forbidden_paths) + tuple(args.forbid_path)
    if args.allow_domain:
        policy.allowed_domains = tuple(args.allow_domain)
    if args.forbid_domain:
        policy.forbidden_domains = tuple(policy.forbidden_domains) + tuple(
            args.forbid_domain
        )
    if args.max_processes is not None:
        policy.max_processes = args.max_processes


def _looks_like_policy_v1(text: str) -> bool:
    """Is this document Policy V1, rather than an existing V3 policy file?

    Policy V1 *requires* a top-level ``version`` field, and the V3 policy schema
    has no such field - its loader rejects unknown keys - so the two formats
    cannot be confused in either direction. A document with ``version`` is V1;
    anything else keeps the V3 path it has today.

    This parse is a discriminator, not a validation: the chosen loader re-parses
    the same text strictly, so duplicate keys, non-finite numbers and every other
    refusal still come from the strict loader. A file that is not JSON at all
    falls through to the V3 loader, which reports the syntax error exactly as it
    does now.
    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(document, dict) and "version" in document


def _load_policy_source(args: argparse.Namespace) -> _PolicySource:
    """Load the policy in force, before any protected process is launched.

    Every failure here is a failure to launch: the caller reports it and exits
    non-zero without starting a child.
    """
    path = getattr(args, "policy", None)
    if not path:
        policy = Policy(workspace_root=args.workspace)
        _apply_v3_overrides(args, policy)
        return _PolicySource(policy=policy, session_timeout=args.timeout)

    try:
        with open(path, "rb") as handle:
            text = handle.read().decode("utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise PolicyError(f"policy file {path} is not valid UTF-8: {exc}") from exc

    if not _looks_like_policy_v1(text):
        policy = Policy.from_json(text)
        policy.workspace_root = args.workspace
        _apply_v3_overrides(args, policy)
        return _PolicySource(policy=policy, session_timeout=args.timeout)

    from .policy_v1 import loads_policy
    from .policy_v1_runtime import project_policy_v1

    conflicting = [flag for attribute, flag in _V3_SHAPING_FLAGS if getattr(args, attribute, None)]
    if conflicting:
        raise PolicyError(
            "a Policy V1 document defines its own filesystem, network and process "
            "rules, so " + ", ".join(conflicting) + " cannot be combined with it; "
            "express the restriction in the document instead"
        )

    document = loads_policy(text, source=path)
    projection = project_policy_v1(document, workspace_root=args.workspace)

    # ``process.max_runtime_seconds`` becomes a real supervisor ceiling: the
    # session timeout is enforced by the kill switch. An explicit ``--timeout``
    # still applies, and the stricter of the two wins.
    document_timeout = float(document.process.max_runtime_seconds)
    session_timeout = (
        document_timeout
        if args.timeout is None
        else min(float(args.timeout), document_timeout)
    )
    return _PolicySource(
        policy=projection.policy,
        tripwires=projection.tripwires,
        projection=projection,
        session_timeout=session_timeout,
    )


def cmd_run(args: argparse.Namespace) -> int:
    command = list(args.protected_command or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print(
            "watcher run: no command given; use: watcher run -- python agent.py",
            file=sys.stderr,
        )
        return 2

    if getattr(args, "enforced", False) and args.inline:
        print(
            "watcher run: --enforced is incompatible with --inline; the in-process "
            "Watcher shares the workload's address space and cannot contain it",
            file=sys.stderr,
        )
        return 2

    # The policy is loaded and validated *before* anything is launched, so an
    # unenforceable document cannot leave a half-protected child running.
    try:
        source = _load_policy_source(args)
    except PolicyError as exc:
        print(f"watcher run: {exc}", file=sys.stderr)
        return 2

    if args.inline:
        return _cmd_run_inline(args, command, source)
    return _cmd_run_v2(args, command, source)


def _cmd_run_inline(
    args: argparse.Namespace, command: Sequence[str], source: _PolicySource
) -> int:
    """V1 behaviour: the Watcher lives inside this process."""
    watcher = PoEWatcher(
        policy=source.policy, workspace_root=args.workspace, tripwires=source.tripwires
    )
    session = watcher.protect(list(command), cwd=args.workspace)

    with session:
        try:
            exit_code = int(session.wait(timeout=source.session_timeout))
        except subprocess.TimeoutExpired:
            watcher.kill(reason="MAX_RUNTIME_EXCEEDED", process=session.process)
            exit_code = TIMEOUT_EXIT_CODE

    if watcher.killed:
        exit_code = KILLED_EXIT_CODE

    if args.trace_out:
        watcher.export_trace(args.trace_out)
    else:
        watcher.seal()

    if not args.quiet:
        summary: dict[str, Any] = session.summary()
        summary["mode"] = "inline (V1)"
        summary["trace"] = args.trace_out
        summary["verification"] = watcher.verify().summary()
        print(json.dumps(summary, indent=2))

    return exit_code


def _build_child_env(values: "Sequence[str]") -> dict[str, str]:
    """Parse repeated ``KEY=VALUE`` options into a child environment."""
    env: dict[str, str] = {}
    for item in values or ():
        key, separator, value = str(item).partition("=")
        if not separator or not key:
            raise SystemExit(
                f"watcher run: --child-env expects KEY=VALUE, got {item!r}"
            )
        env[key] = value
    return env


def _cmd_run_v2(
    args: argparse.Namespace, command: Sequence[str], source: _PolicySource
) -> int:
    """V2/V3: an external supervisor owns policy, PoE, tripwires and the kill switch."""
    from .enforcement import EnforcementMode
    from .supervisor import DaemonConfig, WatcherDaemon

    enforced = bool(getattr(args, "enforced", False))
    containment = _build_containment_profile(args) if enforced else None

    config = DaemonConfig(
        command=list(command),
        policy=source.policy,
        tripwires=source.tripwires,
        workspace_root=args.workspace,
        cwd=args.workspace,
        storage_root=args.storage_root,
        trace_out=args.trace_out,
        child_env=_build_child_env(getattr(args, "child_env", None)),
        ipc_timeout=args.ipc_timeout,
        fail_mode=args.fail_mode,
        heartbeat_interval=args.heartbeat_interval,
        heartbeat_timeout=args.heartbeat_timeout,
        heartbeat_action=args.heartbeat_action,
        ipc_lost_action=args.ipc_lost_action,
        session_timeout=source.session_timeout,
        stdout=None if args.quiet else sys.stderr,
        enforcement=EnforcementMode.ENFORCED if enforced else EnforcementMode.OFF,
        containment=containment,
        enforcement_runtime_root=getattr(args, "enforcement_runtime_root", None),
    )

    daemon = WatcherDaemon(config)
    with supervisor_signal_handlers(daemon):
        exit_code = daemon.run()

    if daemon.internal_error:
        print(f"watcher supervisor error: {daemon.internal_error}", file=sys.stderr)

    if not args.quiet:
        metadata = daemon.stats()["metadata"]
        prepared = daemon.prepared
        kill_record = daemon.watcher.kill_record if prepared else None
        summary = {
            "mode": "enforced (V3)" if daemon.enforcement_mode.value == "enforced" else "supervisor (V2)",
            "session_id": daemon.session_id,
            "status": daemon.state.value,
            "exit_code": exit_code,
            "killed": daemon.killed,
            "kill_reason": kill_record.reason if kill_record else None,
            "events": len(daemon.trace) if prepared else 0,
            "final_hash": (
                daemon.trace.declared_final_hash if prepared else None
            ),
            "verification": daemon.verify().summary() if prepared else None,
            "storage": daemon.storage.root,
            "trace": daemon.paths.trace_path if daemon.paths else None,
            "export": args.trace_out,
            "supervisor_error": daemon.internal_error or None,
            "ipc": metadata.get("ipc", {}).get("stats") if metadata else None,
            "enforcement": (metadata or {}).get("enforcement"),
        }
        if daemon.enforcement_refused:
            summary["enforcement_refused"] = daemon.enforcement_refused
        if source.projection is not None:
            projected = source.projection.to_dict()
            summary["policy"] = {
                "format": projected["policy_format"],
                "document_digest": projected["policy_document_digest"],
                "enforced": projected["enforced_here"],
                "not_applicable": projected["not_applicable"],
                "refused": projected["refused_here"],
            }
        print(json.dumps(summary, indent=2))

        if daemon.enforcement_refused:
            print(
                "watcher run: enforced containment could not be applied, so the "
                "command was NOT run. " + daemon.enforcement_refused,
                file=sys.stderr,
            )
        elif prepared:
            verification = daemon.verify()
            if not verification.valid:
                print(
                    "warning: trace failed verification: "
                    + ", ".join(verification.signals),
                    file=sys.stderr,
                )

    return exit_code


def _build_containment_profile(args: argparse.Namespace):
    """Resolve ``--containment-profile`` plus the individual V3 overrides."""
    import dataclasses

    from .enforcement import PROFILE_PRESETS, ContainmentProfile, NetworkMode, get_preset

    requested = getattr(args, "containment_profile", None)
    if not requested:
        profile = get_preset("research-strict")
    elif requested in PROFILE_PRESETS:
        profile = get_preset(requested)
    else:
        try:
            profile = ContainmentProfile.from_file(requested)
        except FileNotFoundError:
            print(
                f"watcher run: containment profile not found: {requested!r} "
                f"(presets: {', '.join(sorted(PROFILE_PRESETS))})",
                file=sys.stderr,
            )
            raise SystemExit(2) from None
        except (OSError, ValueError) as exc:
            print(
                f"watcher run: cannot read containment profile {requested!r}: {exc}",
                file=sys.stderr,
            )
            raise SystemExit(2) from exc

    backend = getattr(args, "enforcement_backend", None)
    if backend:
        profile = dataclasses.replace(profile, backend=backend)

    network = getattr(args, "network", None)
    if network:
        profile = dataclasses.replace(profile, network=NetworkMode(network))

    read_only_root = getattr(args, "read_only_root", None)
    if read_only_root is not None:
        profile = dataclasses.replace(
            profile,
            filesystem=dataclasses.replace(
                profile.filesystem, read_only_root=bool(read_only_root)
            ),
        )

    memory = getattr(args, "memory", None)
    if memory is not None:
        if memory <= 0:
            print("watcher run: --memory must be positive", file=sys.stderr)
            raise SystemExit(2)
        profile = dataclasses.replace(
            profile,
            resources=dataclasses.replace(profile.resources, memory_mb=memory),
        )

    cpus = getattr(args, "cpus", None)
    if cpus is not None:
        if cpus <= 0:
            print("watcher run: --cpus must be positive", file=sys.stderr)
            raise SystemExit(2)
        profile = dataclasses.replace(
            profile, resources=dataclasses.replace(profile.resources, cpus=cpus)
        )

    pids = getattr(args, "pids", None)
    if pids is not None:
        if pids <= 0:
            print("watcher run: --pids must be positive", file=sys.stderr)
            raise SystemExit(2)
        profile = dataclasses.replace(
            profile,
            processes=dataclasses.replace(profile.processes, max_processes=pids),
        )

    if getattr(args, "allow_reduced_protection", False):
        # An explicit, recorded acknowledgement that the session may run without
        # a requested resource control this backend cannot apply. It is part of
        # the profile, so it is covered by the profile digest.
        profile = dataclasses.replace(profile, allow_reduced_protection=True)

    # A refused profile is a configuration error, reported before anything is
    # started: an unsafe profile is never silently "adjusted".
    profile.validate()
    return profile


def cmd_doctor(args: argparse.Namespace) -> int:
    """Report what this host can actually enforce."""
    from .enforcement import detect_capabilities

    caps = detect_capabilities(refresh=True)
    if args.json:
        payload = caps.to_dict()
        payload["enforced_mode_available"] = caps.enforced_mode_available
        payload["available_backends"] = list(caps.available_backends)
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(caps.doctor_report())

    requested = getattr(args, "containment_profile", None)
    if requested:
        profile = _build_containment_profile(args)
        print()
        print("=" * 70)
        print(f"profile: {profile.name}")
        print(profile.summary())
        print(f"digest:  {profile.digest()}")
        _print_enforcement_report(profile)

    enforce_ok = caps.enforced_mode_available
    if not args.json and enforce_ok:
        from .enforcement.procfs import filesystem_type

        workspace = os.path.abspath(args.workspace)
        fstype = filesystem_type(workspace)
        reliable = "yes"
        reason = "Linux-native filesystem"

        if not os.path.isdir(workspace):
            # Saying "Landlock did not grant access" for a directory that does
            # not exist would be a misleading reason for a real question.
            reliable = "unknown"
            reason = "the path does not exist"
        else:
            try:
                from .enforcement.linux import landlock_ruleset

                if fstype in landlock_ruleset.UNRELIABLE_FILESYSTEMS:
                    reliable = "NO"
                    reason = (
                        f"Landlock path rules are accepted but not reliably "
                        f"honoured on {fstype!r} filesystems"
                    )
                elif not _probe_workspace_enforceable(workspace)[0]:
                    reliable = "NO"
                    reason = "a Landlock allow-list did not grant access to this path"
            except Exception as exc:  # noqa: BLE001 - the doctor reports, never fails
                reliable = "unknown"
                reason = f"could not probe ({type(exc).__name__})"

        print()
        print(f"workspace:            {workspace}")
        print(f"filesystem:           {fstype}")
        print(f"landlock reach:       {reliable}  ({reason})")
        if reliable == "NO":
            print(
                "  A Landlock allow-list there would make the workspace\n"
                "  unreadable rather than contained, so enforced mode refuses\n"
                "  it. Use a Linux-native workspace (ext4, xfs, btrfs, tmpfs,\n"
                "  overlayfs); on WSL that means a path under /, not /mnt/c."
            )

    return 0 if enforce_ok else 1


def _probe_workspace_enforceable(workspace: str) -> tuple[bool, str]:
    """Ask the Linux primitive whether Landlock reaches ``workspace``."""
    if not sys.platform.startswith("linux"):
        return False, "not Linux"
    from .enforcement.linux import landlock_ruleset

    return landlock_ruleset.probe_path_access(workspace)


def _print_enforcement_report(profile: Any) -> None:
    """Print what the backend will actually enforce, not just what was declared.

    A profile is a declaration; the digest hashes the declaration. This section
    is the honest counterpart: which parts of the declaration the selected
    backend really applies, and which it does not.
    """
    from .enforcement import enforcement_report, report_summary

    backend = str(profile.backend or "auto")
    if backend == "auto":
        from .enforcement.capabilities import detect_capabilities

        available = tuple(detect_capabilities().available_backends)
        backend = available[0] if available else "namespaces"

    report = enforcement_report(profile, backend)
    counts = report_summary(report)["counts"]
    print()
    print(f"enforcement report (backend: {backend})")
    notable = [entry for entry in report if entry.status.value != "ENFORCED"]
    if not notable:
        print("  every declared setting is enforced by this backend")
    for entry in notable:
        print(f"  {entry.status.value:<20} {entry.field}")
        if entry.detail:
            print(f"      {entry.detail}")
    print("  counts: " + ", ".join(f"{name}={counts[name]}" for name in sorted(counts)))


def cmd_status(args: argparse.Namespace) -> int:
    from .supervisor import SessionStorage

    storage = SessionStorage(args.storage_root)
    try:
        metadata = storage.read_metadata(args.session_id)
    except Exception as exc:  # noqa: BLE001 - reported as a clean CLI error
        print(f"watcher status: {exc}", file=sys.stderr)
        return 1

    trace = storage.read_trace(args.session_id)
    verification = TraceVerifier().verify(trace)

    summary = {
        "session_id": args.session_id,
        "status": metadata.get("status"),
        "exit_code": metadata.get("exit_code"),
        "killed": metadata.get("killed"),
        "kill": metadata.get("kill"),
        "events": metadata.get("event_count"),
        "final_hash": metadata.get("final_hash"),
        "verification": verification.summary(),
        "trace": storage.session_paths(args.session_id).trace_path,
    }
    print(json.dumps(summary, indent=2))
    return 0 if verification.valid else 1


def cmd_verify(args: argparse.Namespace) -> int:
    result = TraceVerifier().verify_file(args.trace)
    if not args.quiet:
        print(json.dumps(result.summary(), indent=2))
    return 0 if result.valid else 1


def cmd_demo(args: argparse.Namespace) -> int:
    if getattr(args, "v2", False):
        return _demo_v2()
    return _demo_inline()


def _demo_inline() -> int:
    """A scripted, self-contained walkthrough. No subprocesses required."""
    watcher = PoEWatcher(
        policy=Policy(
            allowed_domains=["github.com"],
            forbidden_paths=["/etc/shadow", "~/.ssh"],
        )
    )

    steps: list[tuple[str, str, str]] = [
        ("network_request", "connect", "https://github.com/ladebw/AAIP"),
        ("network_request", "connect", "https://unknown-domain.example/exfil"),
        ("file_access", "read", "/etc/shadow"),
        ("file_access", "read", "/fake/root_token"),
        ("network_request", "connect", "https://github.com/again"),
    ]

    print("The Watcher - in-process (V1) demonstration")
    print("=" * 60)
    for event_type, action, resource in steps:
        evaluation = watcher.evaluate(event_type, action, resource)
        print(f"  {event_type:16s} {resource:42s} -> {evaluation}")

    print("=" * 60)
    print(f"session killed      : {watcher.killed}")
    print(f"kill reason         : {watcher.kill_record.reason if watcher.kill_record else None}")
    print(f"events in trace     : {len(watcher.trace)}")
    for event in watcher.trace:
        print(f"  {event.summary()}")

    verification = watcher.verify()
    print()
    print("=" * 60)
    print(f"trace verification  : {verification}")
    print(f"final hash          : {watcher.trace.final_hash}")
    return 0 if verification.valid else 1


def _demo_v2() -> int:
    """External-supervisor demonstration driven by the example agent."""
    from .supervisor import DaemonConfig, WatcherDaemon

    agent = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "v2_agent.py")
    )
    if not os.path.exists(agent):
        print(f"watcher demo --v2: example agent missing at {agent}", file=sys.stderr)
        return 1

    print("The Watcher - external supervisor (V2) demonstration")
    print("=" * 64)

    daemon = WatcherDaemon(
        DaemonConfig(
            command=[sys.executable, agent],
            policy=Policy(
                allowed_domains=["github.com"],
                forbidden_paths=["/etc/shadow"],
            ),
            cwd=os.getcwd(),
            child_env={"WATCHER_AGENT_MODE": "tripwire", "WATCHER_AGENT_LINGER": "1"},
            heartbeat_interval=1.0,
            heartbeat_timeout=10.0,
            session_timeout=30.0,
            stdout=sys.stderr,
        )
    )
    exit_code = daemon.run()

    print("=" * 64)
    print(f"session id          : {daemon.session_id}")
    print(f"final state         : {daemon.state.value}")
    print(f"exit code           : {exit_code}")
    print(f"killed              : {daemon.killed}")
    print(f"storage             : {daemon.storage.root}")

    if not daemon.prepared:
        print(f"supervisor error    : {daemon.internal_error}", file=sys.stderr)
        return 1

    kill_record = daemon.watcher.kill_record
    print(f"kill reason         : {kill_record.reason if kill_record else None}")
    print()
    print("trace:")
    for event in daemon.trace:
        print(f"  {event.summary()}")
    print()
    print(f"verification        : {daemon.verify()}")
    print(f"final hash          : {daemon.trace.declared_final_hash}")
    return 0 if daemon.verify().valid else 1


def cmd_policy(args: argparse.Namespace) -> int:
    """Validate or digest a Policy V1 document.

    Exit codes follow the existing convention: 0 for success, 2 for a
    configuration error the operator has to fix. A validation failure prints one
    line per problem, each starting with the field path, so the output can be
    read at a glance and parsed without prose matching.
    """
    from .exceptions import PolicyParseError, PolicyValidationError
    from .policy_v1 import load_policy

    command = getattr(args, "policy_command", None)
    path = args.file

    try:
        policy = load_policy(path)
    except PolicyParseError as exc:
        print(f"watcher policy {command}: {exc}", file=sys.stderr)
        return 2
    except PolicyValidationError as exc:
        for issue in exc.issues or ():
            print(str(issue), file=sys.stderr)
        if not exc.issues:
            print(f"watcher policy {command}: {exc.summary}", file=sys.stderr)
        return 2

    if command == "validate":
        print("VALID Policy V1")
        return 0

    if command == "digest":
        if getattr(args, "json", False):
            print(
                json.dumps(
                    {
                        "version": policy.version,
                        "name": policy.name,
                        "document_digest": policy.document_digest,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(policy.document_digest)
        return 0

    print(f"watcher policy: unknown subcommand {command!r}", file=sys.stderr)
    return 2


def main(argv: "Sequence[str] | None" = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "run":
        return cmd_run(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "verify":
        return cmd_verify(args)
    if args.command == "demo":
        return cmd_demo(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "policy":
        return cmd_policy(args)

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
