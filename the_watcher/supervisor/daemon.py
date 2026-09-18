"""The external Watcher daemon (per-session supervisor).

This is the trusted component. It owns, and the protected process never does:

* the authoritative :class:`~the_watcher.watcher.policy.Policy`
* the authoritative :class:`~the_watcher.watcher.tripwire.TripwireRegistry`
* the authoritative :class:`~the_watcher.poe.recorder.Recorder` and trace
* the authoritative :class:`~the_watcher.watcher.kill_switch.KillSwitch`
* process supervision and the protected process handle
* trace storage and the final trace hash
* the IPC listener and the session token

Flow::

    CLI ──▶ WatcherDaemon.run()
              ├─ create session + storage
              ├─ bind IPC endpoint, generate session token
              ├─ launch protected process (a CHILD of the daemon)
              ├─ serve authenticated IPC requests, evaluating policy
              ├─ on KILL: engage the kill switch, terminate the tree, seal
              └─ write trace.json + metadata.json

The protected process receives only connection details. It never receives
policy configuration, the storage path, tripwire definitions, kill-switch
internals or any supervisor handle.

Honest scope: this creates process separation and an external control plane.
It does **not** contain a hostile process running with the same OS privileges,
which can still attack the daemon or bypass the instrumented API entirely.
"""

from __future__ import annotations

import enum
import os
import secrets
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Mapping, Sequence

from ..exceptions import (
    ContainmentRefused,
    ContainmentStartError,
    EnforcementUnavailable,
    IpcDrainTimeout,
    ProtocolError,
    SessionStateError,
    TraceSealedError,
)
from ..enforcement import (
    ContainmentProfile,
    ContainmentState,
    EnforcementMode,
    SandboxSpec,
    enforcement_report,
    get_preset,
    report_summary,
    select_backend,
    unsupported_summary,
)
from ..ipc.client import (
    ENV_ENDPOINT,
    ENV_FAIL_MODE,
    ENV_FAMILY,
    ENV_HEARTBEAT_INTERVAL,
    ENV_PROTOCOL_VERSION,
    ENV_SESSION_ID,
    ENV_TIMEOUT,
    ENV_TOKEN,
)
from ..ipc.protocol import (
    WATCHER_IPC_VERSION,
    ErrorCode,
    IpcLimits,
    MessageType,
    sanitize_text,
    strip_authoritative_fields,
    validate_payload,
)
from ..ipc.server import ClientContext, IpcServer
from ..ipc.transport import IpcListener, LocalEndpoint, create_endpoint
from ..poe import EventType
from ..poe.event import as_text
from ..watcher.decision import Decision, Risk
from ..watcher.authority import (
    AUTHORITATIVE_NAMESPACE,
    AuthoritativeFacts,
    client_forged_reserved_namespace,
)
from ..watcher.policy import Policy
from ..watcher.tripwire import TripwireRegistry
from ..watcher.watcher import PoEWatcher
from .process_supervisor import ProcessSupervisor
from .session import SessionState, SessionStateMachine
from .storage import SessionStorage

__all__ = [
    "DaemonConfig",
    "SupervisoryAction",
    "WatcherDaemon",
    "KILLED_EXIT_CODE",
    "ENFORCEMENT_REFUSED_EXIT_CODE",
]

KILLED_EXIT_CODE = 137

#: Returned when enforced mode was requested but could not be honoured. The
#: session never reaches a state where the workload has run unprotected.
ENFORCEMENT_REFUSED_EXIT_CODE = 78

#: Environment keys the daemon strips before handing the environment to the
#: protected process. Any ``WATCHER_*`` key is removed, then only the
#: connection details are added back.
_ENV_PREFIX = "WATCHER_"

#: Client-provided handshake fields that are safe to copy into the trace.
_SAFE_CLIENT_FIELDS = ("python", "platform", "runtime")


class SupervisoryAction(str, enum.Enum):
    """What the supervisor does when it detects a problem on its own."""

    RECORD = "record"
    QUARANTINE = "quarantine"
    KILL = "kill"

    @classmethod
    def parse(cls, value: "SupervisoryAction | str", field_name: str) -> "SupervisoryAction":
        if isinstance(value, SupervisoryAction):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ValueError(
                f"invalid {field_name}: {value!r} "
                f"(expected one of {', '.join(m.value for m in cls)})"
            ) from exc


@dataclass
class DaemonConfig:
    """Everything the supervisor needs to run one protected session."""

    command: Sequence[str] = field(default_factory=tuple)
    policy: "Policy | None" = None
    tripwires: "TripwireRegistry | None" = None
    workspace_root: str = "."
    cwd: "str | None" = None
    child_env: Mapping[str, str] = field(default_factory=dict)

    session_id: "str | None" = None
    storage_root: "str | None" = None
    trace_out: "str | None" = None

    limits: "IpcLimits | None" = None
    ipc_timeout: float = 5.0
    #: How long the supervisor waits for IPC writers to stop before sealing.
    #: Bounded so a wedged worker cannot hang the session, and exceeded only
    #: as an explicit, recorded failure.
    ipc_drain_timeout: float = 5.0
    fail_mode: str = "fail_closed"

    heartbeat_interval: float = 5.0
    heartbeat_timeout: float = 30.0
    heartbeat_action: SupervisoryAction = SupervisoryAction.RECORD
    record_heartbeats: bool = False

    ipc_lost_action: SupervisoryAction = SupervisoryAction.RECORD
    session_timeout: "float | None" = None
    termination_grace: float = 2.0
    monitor_interval: float = 0.05

    stdout: Any = None
    stderr: Any = None
    clock: "Callable[[], float] | None" = None

    # -- V3 OS-enforced containment --------------------------------------
    #: ``ENFORCED`` moves the trust boundary into the kernel: a denial becomes
    #: an ``EPERM``/``EACCES``/``EROFS`` from the operating system rather than
    #: a message from the Watcher that the workload is free to ignore.
    enforcement: "EnforcementMode | str" = EnforcementMode.OFF
    #: The containment profile. ``None`` selects the ``research-strict`` preset.
    containment: "ContainmentProfile | None" = None
    #: Where the backend keeps guard copies, logs and reports. Defaults to a
    #: supervisor-owned temporary directory outside the workspace.
    enforcement_runtime_root: "str | None" = None

    #: Set to ``True`` only to accept a storage root inside the protected
    #: process's working directory. Refusing by default is what makes "the
    #: agent cannot rewrite its own audit trail" a real property rather than a
    #: hopeful one.
    allow_storage_in_cwd: bool = False

    def __post_init__(self) -> None:
        self.command = tuple(self.command)
        if not self.command:
            raise ValueError("DaemonConfig requires a command to protect")
        self.heartbeat_action = SupervisoryAction.parse(
            self.heartbeat_action, "heartbeat_action"
        )
        self.ipc_lost_action = SupervisoryAction.parse(
            self.ipc_lost_action, "ipc_lost_action"
        )
        if self.heartbeat_interval < 0:
            raise ValueError("heartbeat_interval must be >= 0")
        if self.heartbeat_timeout < 0:
            raise ValueError("heartbeat_timeout must be >= 0")
        if self.termination_grace < 0:
            raise ValueError("termination_grace must be >= 0")
        if isinstance(self.enforcement, EnforcementMode):
            pass
        else:
            try:
                self.enforcement = EnforcementMode(str(self.enforcement).lower())
            except ValueError as exc:
                raise ValueError(
                    f"invalid enforcement mode: {self.enforcement!r} "
                    "(expected 'off' or 'enforced')"
                ) from exc
        if self.enforcement is EnforcementMode.ENFORCED and self.containment is None:
            self.containment = get_preset("research-strict")
        if self.containment is not None:
            self.containment.validate()

    @property
    def heartbeat_enabled(self) -> bool:
        return self.heartbeat_interval > 0 and self.heartbeat_timeout > 0

    @property
    def enforced(self) -> bool:
        return self.enforcement is EnforcementMode.ENFORCED


class WatcherDaemon:
    """Per-session supervisor: the authority for one protected workload."""

    def __init__(self, config: DaemonConfig) -> None:
        self._config = config
        self._clock = config.clock or time.time

        self._session_id: str = config.session_id or uuid.uuid4().hex
        self._token: str = ""
        self._lock = threading.RLock()
        self._quit = threading.Event()
        #: Set by :meth:`request_shutdown` (including from a signal handler).
        #: The supervision loop turns it into an ordinary, recorded kill.
        self._shutdown_requested = False
        self._shutdown_reason = ""
        self._started = False
        self._finalised = False
        #: Set under ``_lock`` as the first act of finalisation. Any thread
        #: that could append to the trace checks it under the same lock, so
        #: once it is set no new authoritative write can begin.
        self._shutting_down = False
        self._exit_code: int = 1
        self._internal_error: str = ""

        self._state = SessionStateMachine(clock=self._clock)
        self._storage = SessionStorage(config.storage_root)
        self._paths = None

        self._policy = config.policy or Policy(workspace_root=config.workspace_root)
        self._tripwires = config.tripwires
        self._watcher: "PoEWatcher | None" = None

        self._endpoint: "LocalEndpoint | None" = None
        self._listener: "IpcListener | None" = None
        self._server: "IpcServer | None" = None
        self._process: "ProcessSupervisor | None" = None

        self._last_heartbeat: "float | None" = None
        self._heartbeat_count = 0
        self._heartbeat_lost = False
        self._client_authenticated = False
        self._client_said_goodbye = False
        self._termination_recorded = False
        self._started_at: "int | None" = None
        self._metadata: dict[str, Any] = {}

        # Shutdown bookkeeping. ``_ipc_drain_failed`` is non-empty when the
        # writers did not stop in time, which makes the session a failure
        # rather than a clean stop.
        self._ipc_drain: Any = None
        self._ipc_drain_failed: str = ""
        self._sealed_verified: "bool | None" = None

        # V3 containment state. Empty unless enforced mode is active.
        self._enforcer: Any = None
        self._unit: Any = None
        self._evidence: Any = None
        self._containment_termination: "dict[str, Any] | None" = None
        self._enforcement_refused = ""

    # -- accessors -------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def state(self) -> SessionState:
        return self._state.state

    @property
    def state_machine(self) -> SessionStateMachine:
        return self._state

    def state_snapshot(self) -> dict[str, Any]:
        """Full state-machine view, including the transition history."""
        return self._state.to_dict()

    def verify(self):
        """Verify the authoritative trace's hash chain."""
        if self._watcher is None:
            raise SessionStateError("daemon has not been started")
        return self._watcher.trace.verify()

    @property
    def trace(self):
        self._require_prepared()
        return self._watcher.trace

    @property
    def watcher(self) -> PoEWatcher:
        self._require_prepared()
        return self._watcher

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def storage(self) -> SessionStorage:
        return self._storage

    @property
    def paths(self):
        return self._paths

    @property
    def endpoint(self) -> "LocalEndpoint | None":
        return self._endpoint

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def internal_error(self) -> str:
        return self._internal_error

    @property
    def ipc_drain(self) -> Any:
        """Result of the IPC drain, or ``None`` if it never ran."""
        return self._ipc_drain

    @property
    def ipc_drain_failed(self) -> str:
        """Non-empty when IPC writers did not stop before the deadline."""
        return self._ipc_drain_failed

    @property
    def sealed_verified(self) -> "bool | None":
        """``True``/``False`` once the sealed trace has been verified."""
        return self._sealed_verified

    @property
    def process(self) -> "ProcessSupervisor | None":
        return self._process

    @property
    def enforcement_mode(self) -> EnforcementMode:
        return self._config.enforcement

    @property
    def contained(self) -> bool:
        """``True`` when the workload is actually running inside a sandbox."""
        return self._unit is not None

    @property
    def enforcer(self) -> Any:
        return self._enforcer

    @property
    def unit(self) -> Any:
        return self._unit

    @property
    def evidence(self) -> Any:
        return self._evidence

    @property
    def containment_termination(self) -> "dict[str, Any] | None":
        return self._containment_termination

    @property
    def containment_profile(self) -> "ContainmentProfile | None":
        return self._config.containment

    @property
    def enforcement_refused(self) -> str:
        """Non-empty when enforced mode was requested but could not be applied."""
        return self._enforcement_refused

    @property
    def killed(self) -> bool:
        return bool(self._watcher and self._watcher.killed)

    @property
    def prepared(self) -> bool:
        """``True`` once the session exists and the trace can be read.

        A daemon can fail during setup (bad storage root, unresolvable
        command) and still be inspected safely; callers that report on a
        daemon must check this first.
        """
        return self._watcher is not None

    def _require_prepared(self) -> None:
        if self._watcher is None:
            raise SessionStateError("daemon has not been started")

    # -- orchestration ---------------------------------------------------

    def run(self) -> int:
        """Run the full session lifecycle and return a process exit code.

        Never raises: a supervisor failure is recorded in the trace and
        surfaced through :attr:`internal_error`, because the audit trail
        matters more than propagating the exception.
        """
        exit_code: "int | None" = None
        try:
            self._prepare()
            self._serve()
            exit_code = self._watch_process()
        except (EnforcementUnavailable, ContainmentRefused) as exc:
            # An enforcement mode that cannot be honoured is refused, never
            # downgraded. The workload is never started unprotected.
            self._enforcement_refused = f"{type(exc).__name__}: {sanitize_text(str(exc), 400)}"
            self._internal_error = self._enforcement_refused
            self._state.transition_quiet(SessionState.FAILED, "enforcement refused")
        except ContainmentStartError as exc:
            self._enforcement_refused = f"{type(exc).__name__}: {sanitize_text(str(exc), 400)}"
            self._internal_error = self._enforcement_refused
            self._state.transition_quiet(SessionState.FAILED, "containment failed to start")
        except Exception as exc:  # noqa: BLE001 - the supervisor must not die
            self._internal_error = f"{type(exc).__name__}: {sanitize_text(str(exc), 200)}"
            self._state.transition_quiet(SessionState.FAILED, "supervisor error")
        finally:
            try:
                self._finalize(exit_code if exit_code is not None else 1)
            except Exception as exc:  # noqa: BLE001
                if not self._internal_error:
                    self._internal_error = (
                        f"finalize {type(exc).__name__}: {sanitize_text(str(exc), 200)}"
                    )

        if self._enforcement_refused:
            return ENFORCEMENT_REFUSED_EXIT_CODE
        if self.killed:
            return KILLED_EXIT_CODE
        return self._exit_code

    def stop(self, reason: str = "SUPERVISOR_STOP") -> None:
        """Ask the supervisor to kill the session. Safe from any thread.

        The check and the kill happen under the daemon lock, and finalisation
        claims that lock before it seals. So either this kill completes before
        finalisation starts — and its event is part of the sealed trace — or
        finalisation has already begun and the kill is skipped. There is no
        interleaving in which a kill is appended after the seal.
        """
        with self._lock:
            if (
                self._watcher is not None
                and not self._watcher.killed
                and not self._shutting_down
            ):
                self._kill_locked(reason)
        self._quit.set()

    # -- setup -----------------------------------------------------------

    def _prepare(self) -> None:
        if self._watcher is not None:
            return

        # Enforcement is validated before anything else exists, so a host that
        # cannot contain the workload fails before a single byte is written
        # or a single process is started.
        if self._config.enforced:
            self._prepare_enforcer()

        self._token = secrets.token_urlsafe(32)
        self._paths = self._storage.create_session(self._session_id)

        # The authoritative trace must not be reachable from the protected
        # process's working directory.
        effective_cwd = self._config.cwd or os.getcwd()
        if not self._config.allow_storage_in_cwd:
            self._storage.assert_outside(effective_cwd)

        self._watcher = PoEWatcher(
            policy=self._policy,
            tripwires=self._tripwires,
            session_id=self._session_id,
            clock=self._clock,
            workspace_root=self._config.workspace_root,
        )

        self._record(
            EventType.SESSION_CREATED,
            action="create",
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="supervisor session created",
            metadata={
                "policy": self._policy.name,
                "tripwires": len(self._watcher.tripwires),
                "protocol_version": WATCHER_IPC_VERSION,
                "fail_mode": self._config.fail_mode,
                "heartbeat_enabled": self._config.heartbeat_enabled,
                "enforcement": self._config.enforcement.value,
            },
        )

        if self._config.enforced:
            self._record_containment_prepared()

    def _prepare_enforcer(self) -> None:
        """Select and validate a containment backend, failing closed."""
        profile = self._config.containment
        assert profile is not None
        self._enforcer = select_backend(
            profile, runtime_root=self._config.enforcement_runtime_root
        )
        self._enforcer.prepare(profile)

    def _record_containment_prepared(self) -> None:
        profile = self._config.containment
        assert profile is not None and self._enforcer is not None
        backend = self._enforcer.backend_name
        # The digest describes what was *declared*. This report describes what
        # the selected backend actually enforces, so the two are recorded
        # together and a digest can never stand alone as a claim of enforcement.
        report = enforcement_report(profile, backend)
        summary = report_summary(report)
        unhonoured_declared = unsupported_summary(profile, backend)[
            "declared_but_unhonoured"
        ]
        self._record(
            EventType.CONTAINMENT_PREPARED,
            action="prepare",
            resource=backend,
            decision=Decision.ALLOW,
            risk=Risk.HIGH if unhonoured_declared else Risk.NORMAL,
            reason="containment backend selected and validated",
            metadata={
                "backend": backend,
                "profile": profile.name,
                "profile_digest": profile.digest(),
                "profile_summary": profile.summary(),
                "network": profile.network.value,
                "read_only_root": profile.filesystem.read_only_root,
                "landlock_required": profile.filesystem.landlock_required,
                "max_processes": profile.processes.max_processes,
                "memory_mb": profile.resources.memory_mb,
                "enforcement_report": summary,
                "declared_but_unhonoured": unhonoured_declared,
                "reduced_protection": bool(
                    profile.is_reduced_protection or unhonoured_declared
                ),
                "allow_reduced_protection": profile.allow_reduced_protection,
            },
        )

    def _serve(self) -> None:
        """Bind IPC, launch the protected process, and mark the session running."""
        self._state.transition(SessionState.STARTING, "supervisor starting")

        limits = self._config.limits or IpcLimits(
            request_timeout=self._config.ipc_timeout
        )
        self._endpoint = create_endpoint(
            self._session_id,
            runtime_dir=self._control_dir() if self._config.enforced else None,
        )
        self._listener = IpcListener(self._endpoint)
        self._server = IpcServer(
            self._listener,
            session_id=self._session_id,
            token=self._token,
            handler=self,
            limits=limits,
            clock=self._clock,
        ).start()

        self._record(
            EventType.IPC_READY,
            action="listen",
            resource=self._endpoint.display,
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="ipc endpoint ready",
            metadata={"family": self._endpoint.family},
        )

        if self._config.enforced:
            self._serve_enforced()
            return

        self._process = ProcessSupervisor(
            self._config.command,
            cwd=self._config.cwd,
            env=self._child_environment(),
            stdout=self._config.stdout,
            stderr=self._config.stderr,
            clock=self._clock,
        )
        pid = self._process.start()
        self._started = True
        self._started_at = int(self._clock())

        assert self._watcher is not None
        self._watcher._attach_process(self._process.local_process)

        self._record(
            EventType.PROCESS_STARTED,
            action="spawn",
            resource=" ".join(self._process.command),
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="protected process started as a child of the supervisor",
            metadata={"pid": pid},
        )

        self._state.transition(SessionState.RUNNING, "process started")

    def _control_dir(self) -> str:
        """A short supervisor-owned directory for the IPC socket.

        It lives under the system temporary directory with a deliberately
        short name because ``AF_UNIX`` paths are capped at around 107 bytes:
        nesting this under the storage root would break as soon as an operator
        chose a reasonably descriptive storage path, and the failure would
        surface as an obscure transport error.

        The directory is created mode 0700 and is not on the sandbox's
        Landlock allow-list, so the workload can only reach the socket through
        the mount the backend places inside the sandbox.
        """
        import tempfile

        path = os.path.join(tempfile.gettempdir(), f"watcher-ipc-{self._session_id[:12]}")
        os.makedirs(path, mode=0o700, exist_ok=True)
        return path

    def _serve_enforced(self) -> None:
        """Launch the workload inside an OS-enforced containment unit.

        The difference from V2 is *where the boundary is*. In V2 the daemon
        decided that an operation was denied and said so over IPC; here the
        workload is placed in namespaces the kernel will not let it leave, and
        every forbidden operation fails with an OS errno regardless of what
        the workload does or whether it ever speaks to the Watcher.
        """
        assert self._enforcer is not None and self._watcher is not None
        profile = self._config.containment
        assert profile is not None

        control_dir = self._control_dir()
        endpoint = self._endpoint
        assert endpoint is not None

        # Ask the backend where things will appear before launching, so the
        # protected process can be told the in-sandbox socket path.
        draft = SandboxSpec(
            command=tuple(self._config.command),
            profile=profile,
            workspace_host=self._config.workspace_root,
            control_dir_host=control_dir,
            cwd_inner=self._config.cwd or self._config.workspace_root,
            unit_key=self._session_id,
        )
        layout = self._enforcer.plan(draft)
        control_inner = layout.get("control_inner") or control_dir

        environment = dict(self._child_environment())
        environment[ENV_ENDPOINT] = os.path.join(
            control_inner, os.path.basename(endpoint.address)
        )

        spec = replace(
            draft,
            environment=environment,
            workspace_inner=layout.get("workspace_inner") or draft.workspace_inner,
            control_dir_inner=control_inner,
            cwd_inner=layout.get("cwd_inner") or draft.cwd_inner,
        )

        # Validate the concrete spec (paths, permissions) before launching.
        self._enforcer.prepare(profile, spec)

        unit = self._enforcer.launch(spec)
        self._unit = unit
        self._process = ProcessSupervisor.adopt(unit.process, clock=self._clock)
        self._started = True
        self._started_at = int(self._clock())
        self._watcher._attach_process(unit.process)

        report = unit.metadata.get("guard_report") or {}
        self._record(
            EventType.CONTAINMENT_STARTED,
            action="contain",
            resource=f"{self._enforcer.backend_name}:{unit.unit_key}",
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="workload launched inside an OS-enforced containment unit",
            metadata={
                "backend": self._enforcer.backend_name,
                "unit_key": unit.unit_key,
                "profile_digest": unit.profile_digest,
                "host_pid": unit.host_pid,
                "launcher_pid": unit.metadata.get("launcher_pid"),
                "namespaces": unit.namespaces.to_dict(),
                "workspace_inner": unit.workspace_inner,
                "control_inner": unit.control_dir_inner,
                "mounts": report.get("mounts"),
            },
        )

        self._record(EventType.NAMESPACES_CREATED, action="unshare", resource="user,pid,mnt,ipc,uts,net",
                     decision=Decision.ALLOW, risk=Risk.NORMAL,
                     reason="kernel namespaces created for the workload",
                     metadata={"namespaces": unit.namespaces.to_dict()})
        self._record(EventType.SECCOMP_ENABLED, action="seccomp", decision=Decision.ALLOW,
                     risk=Risk.NORMAL, reason="syscall filter installed",
                     metadata={"blocked_count": (report.get("seccomp") or {}).get("blocked_count"),
                               "blocked_syscalls": (report.get("seccomp") or {}).get("blocked_syscalls")})
        self._record(EventType.LANDLOCK_ENABLED, action="landlock", decision=Decision.ALLOW,
                     risk=Risk.NORMAL, reason="filesystem allow-list installed",
                     metadata={"abi": (report.get("landlock") or {}).get("abi"),
                               "granted_paths": (report.get("landlock") or {}).get("granted_paths"),
                               "skipped_paths": (report.get("landlock") or {}).get("skipped_paths")})
        self._record(EventType.CAPABILITIES_DROPPED, action="capdrop", decision=Decision.ALLOW,
                     risk=Risk.NORMAL, reason="capabilities cleared and bounding set dropped",
                     metadata=report.get("capabilities") or {})
        self._record(EventType.RESOURCE_LIMIT_APPLIED, action="rlimit", decision=Decision.ALLOW,
                     risk=Risk.NORMAL, reason="resource ceilings applied",
                     metadata=report.get("limits") or {})
        if profile.filesystem.read_only_root:
            self._record(EventType.READ_ONLY_ROOT_ENFORCED, action="remount",
                         decision=Decision.ALLOW, risk=Risk.NORMAL,
                         reason="the container root filesystem was remounted read-only",
                         metadata={"mounts": report.get("mounts")})
        if profile.network.value == "none":
            self._record(EventType.NETWORK_NAMESPACE_CREATED, action="isolate",
                         decision=Decision.ALLOW, risk=Risk.NORMAL,
                         reason="the workload was given its own network namespace",
                         metadata={"network_mode": profile.network.value})

        # Health check: observe the running unit from outside and refuse to
        # continue if what the kernel reports does not match the profile.
        evidence = self._enforcer.inspect(unit)
        self._evidence = evidence

        if not evidence.verified:
            self._record(
                EventType.CONTAINMENT_HEALTH_FAILED,
                action="verify",
                resource=self._enforcer.backend_name,
                decision=Decision.KILL,
                risk=Risk.CRITICAL,
                reason=(
                    "containment could not be verified; treating the sandbox "
                    "as unusable rather than continuing without it"
                ),
                metadata={"problems": list(evidence.problems),
                          "evidence": evidence.to_dict()},
            )
            self._destroy_unit(reason="CONTAINMENT_UNVERIFIED")
            raise ContainmentStartError(
                "containment verification failed: " + "; ".join(evidence.problems)
            )

        self._record(
            EventType.CONTAINMENT_VERIFIED,
            action="verify",
            resource=self._enforcer.backend_name,
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="containment verified from outside the sandbox",
            metadata={
                "evidence": evidence.to_dict(),
                "detail": unit.metadata.get("evidence_detail") or {},
                "summary": evidence.summary(),
            },
        )

        self._record(
            EventType.PROCESS_STARTED,
            action="spawn",
            resource=" ".join(self._config.command),
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="protected process started inside a containment unit",
            metadata={"pid": unit.host_pid, "unit_key": unit.unit_key},
        )

        self._state.transition(SessionState.RUNNING, "contained process started")

    # -- containment teardown -------------------------------------------

    def _destroy_unit(self, reason: str) -> None:
        """Isolate, terminate, and prove the unit is gone. Idempotent."""
        unit = self._unit
        enforcer = self._enforcer
        if unit is None or enforcer is None or self._containment_termination is not None:
            return

        self._record(
            EventType.CONTAINER_TERMINATION_STARTED,
            action="terminate",
            resource=unit.unit_key,
            decision=Decision.KILL,
            risk=Risk.HIGH,
            reason=f"destroying containment unit: {reason}",
            metadata={"unit_key": unit.unit_key, "backend": enforcer.backend_name},
        )

        isolated, isolation_detail = enforcer.isolate_network(unit)
        if isolated:
            self._record(
                EventType.NETWORK_ISOLATED,
                action="isolate",
                resource=unit.unit_key,
                decision=Decision.KILL,
                risk=Risk.HIGH,
                reason=isolation_detail,
                metadata={"network_mode": unit.metadata.get("network_mode"),
                          "network_isolated": bool(unit.metadata.get("network_isolated"))},
            )

        outcome = enforcer.terminate(unit, grace=self._config.termination_grace)
        empty, survivors = enforcer.verify_empty(unit)

        self._record(
            EventType.CONTAINER_TERMINATED,
            action="terminate",
            resource=unit.unit_key,
            decision=Decision.KILL,
            risk=Risk.CRITICAL if survivors else Risk.HIGH,
            reason=f"containment unit {outcome.state.value.lower()}",
            metadata={"outcome": outcome.to_dict(), "isolation": isolation_detail},
        )

        if empty:
            self._record(
                EventType.CONTAINMENT_VERIFIED_EMPTY,
                action="verify_empty",
                resource=unit.unit_key,
                decision=Decision.KILL,
                risk=Risk.HIGH,
                reason=(
                    "no process carrying the unit's namespaces remains"
                ),
                metadata={"namespace": unit.user_namespace},
            )
        else:
            # Protected processes survived termination. There is no honest
            # way to soften this: it is recorded as critical and the session
            # ends in KILL_FAILED.
            unit.state = ContainmentState.KILL_FAILED
            self._record(
                EventType.KILL_FAILED,
                action="verify_empty",
                resource=unit.unit_key,
                decision=Decision.KILL,
                risk=Risk.CRITICAL,
                reason="processes from the containment unit survived termination",
                metadata={
                    "survivors": survivors,
                    "namespace": unit.user_namespace,
                    "outcome": outcome.to_dict(),
                },
            )

        self._containment_termination = {
            "isolated": isolated,
            "isolation_detail": isolation_detail,
            "terminated": outcome.state is ContainmentState.TERMINATED,
            "state": outcome.state.value,
            "empty": empty,
            "survivors": survivors,
            "duration_seconds": outcome.duration_seconds,
            "method": outcome.method,
        }

    def _child_environment(self) -> dict[str, str]:
        """Build the environment for the protected process.

        Every ``WATCHER_*`` key is stripped from the inherited environment
        first, so nothing leaks in by accident. Operator extras from
        ``config.child_env`` are applied next, and the session's own connection
        details are applied **last** so they cannot be overridden.

        Policy configuration, the storage path, tripwire definitions and
        supervisor handles are never included.
        """
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(_ENV_PREFIX)
        }
        endpoint = self._endpoint
        assert endpoint is not None

        env.update({str(k): str(v) for k, v in self._config.child_env.items()})
        env.update(
            {
                ENV_SESSION_ID: self._session_id,
                ENV_ENDPOINT: endpoint.address,
                ENV_TOKEN: self._token,
                ENV_PROTOCOL_VERSION: str(WATCHER_IPC_VERSION),
                ENV_FAMILY: endpoint.family,
                ENV_TIMEOUT: f"{self._config.ipc_timeout:g}",
                ENV_FAIL_MODE: self._config.fail_mode,
                ENV_HEARTBEAT_INTERVAL: f"{self._config.heartbeat_interval:g}",
            }
        )
        return env

    # -- monitoring ------------------------------------------------------

    def _watch_process(self) -> int:
        """Supervise the child until it exits, the session times out, or we stop."""
        assert self._process is not None

        while not self._quit.is_set():
            code = self._process.poll()
            if code is not None:
                return int(code)
            self._check_heartbeat()
            self._check_session_timeout()
            self._quit.wait(self._config.monitor_interval)

        # A stop was requested. If it came from a signal handler it has not
        # killed anything yet - the handler only set the flag - so the
        # controlled shutdown happens here, on the normal path, with the
        # normal lock and the normal kill accounting.
        self._perform_requested_shutdown()

        code = self._process.poll()
        return int(code) if code is not None else 1

    def _perform_requested_shutdown(self) -> None:
        """Turn a shutdown request into an ordinary, recorded kill.

        ``stop`` already kills under the lock, so this only has work to do when
        the request came from somewhere that must not do real work - a signal
        handler calling :meth:`request_shutdown`. A workload that has already
        exited is left alone; finalisation records its real status.
        """
        if not self._shutdown_requested:
            return
        state = self._workload_state()
        if not state["started"] or not state["alive"]:
            return
        with self._lock:
            if self._shutting_down or self.killed:
                return
            self._record(
                EventType.SHUTDOWN_REQUESTED,
                action="shutdown",
                resource=str(self._process.pid) if self._process else "",
                decision=Decision.KILL,
                risk=Risk.HIGH,
                reason=f"controlled shutdown requested: {self._shutdown_reason or 'unspecified'}",
                metadata={"requested_reason": self._shutdown_reason, "source": "signal"},
            )
            self._kill_locked(self._shutdown_reason or "SHUTDOWN_REQUESTED")

    def _record_vanished_client(self) -> None:
        """Record a client that exited without saying goodbye.

        Loss of the control channel is normally noticed by the IPC server's
        worker thread when the socket closes, but that is a race: on Linux the
        supervisor's poll of the child frequently wins, and the trace was then
        sealed without ever recording that the protected process had gone
        silently. The client's own exit status is a trustworthy signal that it
        is gone, so the fact is recorded here as well.

        A client that sent ``session_end`` is not a lost client, and a session
        driven without IPC (V3 enforced mode with no client) must not be
        flagged either.
        """
        if self._client_said_goodbye or not self._client_authenticated:
            return
        if any(event.event_type == EventType.IPC_LOST for event in self.trace):
            return

        with self._lock:
            self._record(
                EventType.IPC_LOST,
                action="ipc_lost",
                resource=self._endpoint.display if self._endpoint else "ipc",
                decision=Decision.DENY,
                risk=Risk.HIGH,
                reason=(
                    "the protected process exited without closing the control "
                    "channel"
                ),
                metadata={
                    "action": self._config.ipc_lost_action.value,
                    "detected_by": "process_exit",
                },
            )

    def _check_heartbeat(self) -> None:
        if (
            not self._config.heartbeat_enabled
            or self._heartbeat_lost
            or self._last_heartbeat is None
        ):
            return

        elapsed = self._clock() - self._last_heartbeat
        if elapsed <= self._config.heartbeat_timeout:
            return

        self._heartbeat_lost = True
        with self._lock:
            self._record(
                EventType.HEARTBEAT_LOST,
                action="heartbeat",
                decision=Decision.DENY,
                risk=Risk.HIGH,
                reason=(
                    f"no heartbeat for {elapsed:.1f}s "
                    f"(timeout {self._config.heartbeat_timeout:g}s)"
                ),
                metadata={
                    "elapsed_seconds": round(elapsed, 3),
                    "timeout_seconds": self._config.heartbeat_timeout,
                    "heartbeats_received": self._heartbeat_count,
                    "action": self._config.heartbeat_action.value,
                },
            )
            self._apply_supervisory_action(
                self._config.heartbeat_action, "HEARTBEAT_LOST"
            )

    def _check_session_timeout(self) -> None:
        limit = self._config.session_timeout
        if limit is None or self._started_at is None:
            return
        elapsed = self._clock() - self._started_at
        if elapsed <= limit:
            return

        with self._lock:
            self._record(
                EventType.SESSION_TIMEOUT,
                action="timeout",
                decision=Decision.KILL,
                risk=Risk.HIGH,
                reason=f"session exceeded {limit:g}s",
                metadata={"elapsed_seconds": round(elapsed, 3), "limit_seconds": limit},
            )
            self._kill_locked("MAX_RUNTIME_EXCEEDED")

    def _apply_supervisory_action(self, action: SupervisoryAction, source: str) -> None:
        if action is SupervisoryAction.RECORD:
            return
        if action is SupervisoryAction.QUARANTINE:
            if self._watcher is not None and not self._watcher.quarantined:
                self._watcher.quarantine(reason=source)
                self._state.transition_quiet(SessionState.QUARANTINED, source)
            return
        if action is SupervisoryAction.KILL:
            self._kill_locked(source)

    # -- kill path -------------------------------------------------------

    def _kill_locked(self, reason: str, triggering_event: Any = None) -> Any:
        """Terminate the session. Must be called with ``self._lock`` held.

        Termination is performed through the supervisor-owned ``LocalProcess``
        (which the kill switch holds as its target), so the external daemon is
        always the component that actually kills the protected tree.
        """
        assert self._watcher is not None

        if self._watcher.killed:
            self._after_kill_locked()
            return self._watcher.kill_record

        local_process = (
            self._process.local_process
            if self._process is not None and self._process.started
            else None
        )

        record = self._watcher.kill(
            reason=reason,
            triggering_event=triggering_event,
            process=local_process,
        )
        # A stopped or destroyed container cannot act again. This runs before
        # the post-kill accounting so the trace records the containment
        # outcome as part of the same kill.
        self._destroy_unit(reason=reason)
        self._after_kill_locked()
        return record

    def _after_kill_locked(self) -> None:
        """Record the termination accounting for a kill. Idempotent.

        Called both when the daemon initiates a kill and when a
        ``PoEWatcher.evaluate`` call decided ``KILL`` during policy evaluation,
        so every kill path produces exactly one ``process_termination`` entry
        carrying the metrics V2 must record.
        """
        if self._termination_recorded or self._watcher is None:
            return
        record = self._watcher.kill_record
        if record is None:
            return

        # A policy-driven kill (decided inside evaluate) never went through
        # _kill_locked, so make sure the container is destroyed here too.
        self._destroy_unit(reason=record.reason)

        self._termination_recorded = True
        termination = dict(record.termination or {})

        if self._process is not None:
            # Keep the supervisor's own view consistent with the trace.
            self._process.note_external_termination(termination)

        self._record(
            EventType.PROCESS_TERMINATION,
            action="terminate_tree",
            resource=str(termination.get("pid", "")),
            decision=Decision.KILL,
            risk=Risk.CRITICAL,
            reason=record.reason,
            metadata={
                "kill_started": record.triggered_at,
                "triggering_event_hash": record.triggering_event_hash,
                "termination_method": termination.get("method"),
                "descendant_count": termination.get("descendant_count", 0),
                "grace_period": termination.get(
                    "grace_period", self._config.termination_grace
                ),
                "forced_termination": termination.get("forced_termination", False),
                "tree_enumerated": termination.get("tree_enumerated", False),
                "termination_result": {
                    "terminated": termination.get("terminated", []),
                    "failed": termination.get("failed", []),
                    "error": termination.get("error", ""),
                },
                "termination_duration_seconds": termination.get("duration_seconds", 0.0),
            },
        )

        self._state.transition_quiet(SessionState.KILLED, record.reason)

    # -- IPC handler interface -------------------------------------------

    def session_snapshot(self) -> dict[str, Any]:
        """State summary returned to an authenticating client."""
        return {
            "state": self._state.state.value,
            "killed": self.killed,
            "heartbeat": {
                "interval": self._config.heartbeat_interval,
                "timeout": self._config.heartbeat_timeout,
                "required": self._config.heartbeat_enabled,
                "action": self._config.heartbeat_action.value,
            },
        }

    def dispatch(
        self, message_type: str, payload: Mapping[str, Any], context: ClientContext
    ) -> dict[str, Any]:
        """Handle one validated client request."""
        readonly = {
            MessageType.SESSION_STATUS.value,
            MessageType.TRACE_INFO.value,
            MessageType.HEARTBEAT.value,
            MessageType.SESSION_END.value,
            MessageType.KILL_REQUEST.value,
        }

        if self._shutting_down and message_type not in readonly:
            # Finalisation has begun, so a write would race the seal. Refusing
            # it here keeps "no new authoritative write once shutdown starts"
            # true at the API surface, not only down in the trace.
            raise ProtocolError(
                ErrorCode.SESSION_TERMINAL, "session is shutting down"
            )

        if self._state.is_terminal:
            evaluating_after_kill = (
                message_type == MessageType.EVALUATE.value and self.killed
            )
            if message_type not in readonly and not evaluating_after_kill:
                raise ProtocolError(
                    ErrorCode.SESSION_TERMINAL, "session has finished"
                )

        try:
            if message_type == MessageType.EVALUATE.value:
                return self._handle_evaluate(payload, context)
            if message_type == MessageType.EVENT.value:
                return self._handle_event(payload, context)
            if message_type == MessageType.HEARTBEAT.value:
                return self._handle_heartbeat(payload, context)
            if message_type == MessageType.SESSION_STATUS.value:
                return self._handle_status()
            if message_type == MessageType.TRACE_INFO.value:
                return self._handle_trace_info()
            if message_type == MessageType.KILL_REQUEST.value:
                return self._handle_kill_request(payload, context)
            if message_type == MessageType.SESSION_END.value:
                return self._handle_session_end(payload, context)

            raise ProtocolError(
                ErrorCode.UNKNOWN_MESSAGE, "unsupported message type"
            )
        except TraceSealedError as exc:
            # The trace is sealed, so the session is finished and nothing more
            # may be recorded. A late writer is refused outright: answering it
            # would mean choosing between corrupting the sealed trace and
            # replying with a decision that was never recorded. Read-only
            # requests above are unaffected, so a client can still ask what
            # happened.
            raise ProtocolError(
                ErrorCode.SESSION_TERMINAL,
                "session trace is sealed and cannot accept new events",
            ) from exc

    def _handle_evaluate(
        self, payload: Mapping[str, Any], context: ClientContext
    ) -> dict[str, Any]:
        request = self._sanitize_client_payload(payload, context, "evaluate")
        with self._lock:
            assert self._watcher is not None
            evaluation = self._watcher.evaluate(
                request["event_type"],
                request["action"],
                request["resource"],
                metadata=request["metadata"],
            )
            if self._watcher.killed:
                # Policy (or a tripwire) decided KILL during evaluation; make
                # sure the termination accounting is recorded exactly once.
                self._after_kill_locked()
            elif self._watcher.quarantined and not self._state.quarantined:
                # A policy QUARANTINE must be reflected in the session state,
                # not only in the trace.
                self._state.transition_quiet(
                    SessionState.QUARANTINED, evaluation.rule
                )
            return self._decision_payload(evaluation)

    def _handle_event(
        self, payload: Mapping[str, Any], context: ClientContext
    ) -> dict[str, Any]:
        request = self._sanitize_client_payload(payload, context, "event")
        with self._lock:
            assert self._watcher is not None
            event = self._watcher.observe(
                request["event_type"],
                request["action"],
                request["resource"],
                decision=Decision.ALLOW,
                risk=Risk.NORMAL,
                reason="reported by client",
                metadata=request["metadata"],
            )
            return {"recorded": True, "sequence": event.sequence}

    def _handle_heartbeat(
        self, payload: Mapping[str, Any], context: ClientContext
    ) -> dict[str, Any]:
        _, rejected = strip_authoritative_fields(payload)
        with self._lock:
            self._last_heartbeat = self._clock()
            self._heartbeat_count += 1
            if rejected:
                self._record_rejected_fields(rejected, context)
            if self._config.record_heartbeats:
                self._record(
                    EventType.HEARTBEAT,
                    action="heartbeat",
                    decision=Decision.ALLOW,
                    risk=Risk.NORMAL,
                    reason="client heartbeat",
                    metadata={"count": self._heartbeat_count},
                )
            return {
                "acknowledged": True,
                "session_state": self._state.state.value,
                "killed": self.killed,
                "count": self._heartbeat_count,
            }

    def _handle_status(self) -> dict[str, Any]:
        return {
            "session_id": self._session_id,
            "state": self._state.state.value,
            "killed": self.killed,
            "quarantined": bool(self._watcher and self._watcher.quarantined),
            "event_count": len(self._watcher.trace) if self._watcher else 0,
            "terminal": self._state.is_terminal,
        }

    def _handle_trace_info(self) -> dict[str, Any]:
        assert self._watcher is not None
        trace = self._watcher.trace
        return {
            "session_id": self._session_id,
            "state": self._state.state.value,
            "event_count": len(trace),
            "head_hash": trace.head_hash,
            "sealed": trace.sealed,
            "final_hash": trace.declared_final_hash,
        }

    def _handle_kill_request(
        self, payload: Mapping[str, Any], context: ClientContext
    ) -> dict[str, Any]:
        reason = sanitize_text(payload.get("reason") or "CLIENT_REQUESTED_TERMINATION", 200)
        _, rejected = strip_authoritative_fields(payload)
        with self._lock:
            assert self._watcher is not None
            if rejected:
                self._record_rejected_fields(rejected, context)
            if self._watcher.killed:
                # Kill state is irreversible: a client request can never
                # reset, downgrade or re-trigger it.
                return {
                    "killed": True,
                    "already_killed": True,
                    "reason": self._watcher.kill_record.reason
                    if self._watcher.kill_record
                    else None,
                    "session_state": self._state.state.value,
                }
            self._kill_locked(f"CLIENT_REQUEST:{reason}")
            return {
                "killed": True,
                "already_killed": False,
                "reason": reason,
                "session_state": self._state.state.value,
            }

    def _handle_session_end(
        self, payload: Mapping[str, Any], context: ClientContext
    ) -> dict[str, Any]:
        _, rejected = strip_authoritative_fields(payload)
        with self._lock:
            if rejected:
                self._record_rejected_fields(rejected, context)
            # A client that says goodbye is not a lost client, so the
            # disconnect handler must not raise an IPC_LOST alarm for it.
            self._client_said_goodbye = True
        return {
            "acknowledged": True,
            "session_state": self._state.state.value,
        }

    # -- payload sanitisation --------------------------------------------

    def _sanitize_client_payload(
        self, payload: Mapping[str, Any], context: ClientContext, kind: str
    ) -> dict[str, Any]:
        """Strip daemon-owned fields and validate the rest.

        The client is untrusted, so nothing it sends is trusted to be
        well-formed, and it can never supply ``sequence``, ``timestamp``,
        ``previous_hash``, ``event_hash``, ``final_hash``, ``decision`` or
        ``risk``.
        """
        clean, rejected = strip_authoritative_fields(payload)

        event_type = clean.get("event_type")
        action = clean.get("action")
        resource = clean.get("resource", "")
        metadata = clean.get("metadata") or {}

        if not isinstance(event_type, str) or not event_type.strip():
            raise ProtocolError(ErrorCode.BAD_REQUEST, "event_type is required")
        if not isinstance(action, str) or not action.strip():
            raise ProtocolError(ErrorCode.BAD_REQUEST, "action is required")
        if resource is None:
            resource = ""
        if not isinstance(resource, str):
            resource = str(resource)
        if not isinstance(metadata, Mapping):
            raise ProtocolError(ErrorCode.BAD_REQUEST, "metadata must be an object")

        # Re-validate the values actually about to be hashed.
        limits = self._server.limits if self._server else IpcLimits()
        validate_payload(
            {
                "event_type": event_type,
                "action": action,
                "resource": resource,
                "metadata": dict(metadata),
            },
            limits,
        )

        with self._lock:
            if rejected:
                self._record_rejected_fields(rejected, context)
            # A client that supplies the reserved authoritative namespace is
            # trying to write the supervisor's own facts. It cannot take
            # effect - the supervisor overwrites it below - but the attempt is
            # recorded rather than silently dropped.
            if client_forged_reserved_namespace(metadata):
                self._record_rejected_fields(
                    [f"metadata.{AUTHORITATIVE_NAMESPACE}"], context
                )
            return {
                "event_type": event_type,
                "action": action,
                "resource": resource,
                "metadata": {
                    **dict(metadata),
                    "ipc": {
                        "connection_id": context.connection_id,
                        "client_pid": context.client_pid,
                        "kind": kind,
                    },
                    # Written last, so nothing the client sent can survive here.
                    AUTHORITATIVE_NAMESPACE: self._authoritative_facts(
                        event_type, resource
                    ).to_metadata(),
                },
            }

    def _authoritative_facts(self, event_type: str, resource: str) -> AuthoritativeFacts:
        """The facts the supervisor observed for one request.

        Only what the supervisor can genuinely establish is included. The
        process-tree size is measured only for ``process_creation`` events,
        because it costs a ``/proc`` walk and no other rule consumes it.
        """
        process_count: "int | None" = None
        if event_type == EventType.PROCESS_CREATION.value and self._process is not None:
            if self._process.started:
                process_count = self._process.process_count()
        runtime_seconds: "int | None" = None
        if self._started_at is not None:
            runtime_seconds = max(0, int(self._clock()) - self._started_at)
        return AuthoritativeFacts(
            resource=resource,
            process_count=process_count,
            runtime_seconds=runtime_seconds,
            session_state=self._state.state.value,
        )

    def _record_rejected_fields(
        self, rejected: Sequence[str], context: ClientContext
    ) -> None:
        """Record that a client tried to supply daemon-owned fields."""
        self._record(
            EventType.CLIENT_FIELD_REJECTED,
            action="reject_authoritative_fields",
            resource=context.connection_id,
            decision=Decision.ALLOW,
            risk=Risk.ELEVATED,
            reason="client supplied fields only the daemon may set",
            metadata={"fields": sorted(set(rejected)), "client_pid": context.client_pid},
        )

    def _decision_payload(self, evaluation: Any) -> dict[str, Any]:
        return {
            "decision": evaluation.decision.value,
            "risk": evaluation.risk.value,
            "reason": evaluation.reason,
            "rule": evaluation.rule,
            "session_state": self._state.state.value,
            "killed": self.killed,
        }

    # -- server hooks ----------------------------------------------------

    def on_client_connected(self, context: ClientContext) -> None:
        with self._lock:
            self._record(
                EventType.CLIENT_CONNECTED,
                action="connect",
                resource=context.connection_id,
                decision=Decision.ALLOW,
                risk=Risk.NORMAL,
                reason="ipc client connected",
                metadata={"client_pid": context.client_pid},
            )

    def on_client_authenticated(self, context: ClientContext) -> None:
        with self._lock:
            self._client_authenticated = True
            # Start the heartbeat clock from authentication, so a client that
            # connects and then goes silent is still detected.
            self._last_heartbeat = self._clock()
            self._record(
                EventType.CLIENT_AUTHENTICATED,
                action="authenticate",
                resource=context.connection_id,
                decision=Decision.ALLOW,
                risk=Risk.NORMAL,
                reason="ipc client authenticated",
                metadata=context.to_dict(),
            )

    def on_client_disconnected(self, context: ClientContext, reason: str) -> None:
        with self._lock:
            self._record(
                EventType.CLIENT_DISCONNECTED,
                action="disconnect",
                resource=context.connection_id,
                decision=Decision.ALLOW,
                risk=Risk.NORMAL,
                reason=sanitize_text(reason, 120),
                metadata={"requests_served": context.requests_served},
            )

            still_running = (
                not self._state.is_terminal
                and self._process is not None
                and self._process.alive
            )
            # Only a *total* loss of the authenticated control channel is an
            # incident: an agent may legitimately open extra connections, and
            # a client that said goodbye is not lost.
            no_other_clients = (
                self._server.authenticated_count == 0 if self._server else True
            )
            if (
                context.authenticated
                and still_running
                and no_other_clients
                and not self._client_said_goodbye
            ):
                self._record(
                    EventType.IPC_LOST,
                    action="ipc_lost",
                    decision=Decision.DENY,
                    risk=Risk.ELEVATED,
                    reason=(
                        "authenticated client disconnected while the process is "
                        f"still running: {sanitize_text(reason, 80)}"
                    ),
                    metadata={"action": self._config.ipc_lost_action.value},
                )
                self._apply_supervisory_action(
                    self._config.ipc_lost_action, "IPC_LOST"
                )

    def on_protocol_violation(
        self, code: str, detail: str, context: ClientContext
    ) -> None:
        with self._lock:
            self._record(
                EventType.IPC_VIOLATION,
                action=str(code),
                resource=context.connection_id,
                decision=Decision.ALLOW,
                risk=Risk.ELEVATED,
                reason=sanitize_text(detail, 200),
                metadata={"code": str(code)},
            )

    def on_handler_error(self, kind: str, detail: str, context: ClientContext) -> None:
        with self._lock:
            self._record(
                EventType.IPC_VIOLATION,
                action=f"handler_error:{kind}",
                resource=context.connection_id,
                decision=Decision.ALLOW,
                risk=Risk.ELEVATED,
                reason=sanitize_text(detail, 200),
                metadata={"kind": kind},
            )

    # -- recording helpers -----------------------------------------------

    def _scrub(self, value: Any) -> Any:
        """Replace the session token anywhere it might have leaked."""
        token = self._token
        if not token:
            return value
        if isinstance(value, str):
            return value.replace(token, "[REDACTED]") if token in value else value
        if isinstance(value, Mapping):
            return {str(k): self._scrub(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._scrub(item) for item in value]
        return value

    def _record(
        self,
        event_type: Any,
        action: str,
        resource: str = "",
        decision: Any = Decision.ALLOW,
        risk: Any = Risk.NORMAL,
        reason: str = "",
        metadata: "Mapping[str, Any] | None" = None,
    ) -> Any:
        assert self._watcher is not None
        return self._watcher.recorder.record(
            event_type,
            action,
            resource,
            decision=as_text(decision).upper(),
            risk=as_text(risk).upper(),
            reason=self._scrub(str(reason)),
            metadata=self._scrub(dict(metadata or {})),
        )

    # -- finalisation ----------------------------------------------------

    #: How long finalisation waits for a workload it has terminated to
    #: actually disappear before declaring the termination unverified. Bounded
    #: so a wedged process cannot hang the session, and exceeded only as an
    #: explicitly recorded, critical failure.
    FINALIZATION_VERIFY_TIMEOUT = 5.0

    def _workload_state(self) -> dict[str, Any]:
        """What the supervisor can observe about the workload right now.

        ``alive`` is the kernel's answer (``poll()``), never a cached belief.
        """
        process = self._process
        if process is None or not process.started:
            return {"started": False, "alive": False, "returncode": None}
        code = process.poll()
        return {"started": True, "alive": code is None, "returncode": code}

    def _ensure_workload_stopped(self) -> dict[str, Any]:
        """Guarantee no protected workload outlives finalisation.

        This is the Phase 0 Blocker A invariant, and it is the *only* place
        that may decide whether an exit status was observed. Outcomes:

        ``not_started``
            Nothing was ever launched. No exit was observed, and none is
            claimed.
        ``already_exited``
            ``poll()`` returned a real status. That status is authoritative and
            may be recorded as an observed exit.
        ``terminated``
            The workload was still running, so it was terminated and then
            verified gone. The signal-derived status is reported, but it is
            explicitly *not* an observed voluntary exit.
        ``termination_unverified``
            The workload was still running and could not be confirmed gone.
            The caller must treat this as a critical failure and must not write
            an exit event.
        """
        state = self._workload_state()

        if not state["started"]:
            return {
                "phase": "not_started",
                "exit_code": 1,
                "exit_observed": False,
                "termination": None,
                "survivors": [],
            }

        if not state["alive"]:
            return {
                "phase": "already_exited",
                "exit_code": int(state["returncode"] or 0),
                "exit_observed": True,
                "termination": None,
                "survivors": [],
            }

        # The workload outlived the reason we are finalising. Record the
        # request and the initiation *before* doing anything, so the trace
        # shows a deliberate stop rather than an unexplained disappearance.
        pid = self._process.pid if self._process is not None else None
        self._record(
            EventType.SHUTDOWN_REQUESTED,
            action="shutdown",
            resource=str(pid) if pid is not None else "",
            decision=Decision.KILL,
            risk=Risk.HIGH,
            reason=(
                "finalisation was reached while the protected workload was "
                "still running"
            ),
            metadata={
                "phase": "finalization",
                "pid": pid,
                "kill_switch_engaged": self.killed,
                "requested_reason": self._shutdown_reason or None,
                "observed_alive": True,
            },
        )
        self._record(
            EventType.TERMINATION_INITIATED,
            action="terminate_workload",
            resource=str(pid) if pid is not None else "",
            decision=Decision.KILL,
            risk=Risk.HIGH,
            reason="terminating the protected workload before the trace is sealed",
            metadata={
                "pid": pid,
                "grace_seconds": self._config.termination_grace,
                "contained": self._unit is not None,
            },
        )

        termination, survivors, verified = self._terminate_workload_now()
        process = self._process
        reported = process.poll() if process is not None else None

        if verified:
            self._record(
                EventType.TERMINATION_VERIFIED,
                action="verify_termination",
                resource=str(pid) if pid is not None else "",
                decision=Decision.KILL,
                risk=Risk.HIGH,
                reason="the protected workload was observed to be gone",
                metadata={
                    "termination": termination,
                    "survivors": list(survivors),
                    "exit_observed": False,
                    "status_after_termination": reported,
                },
            )
            # The workload did not exit on its own, so this is a failure rather
            # than an exit status. The raw status the kernel reported for the
            # terminated process (typically a signal) is kept in the event
            # metadata above, never presented as a voluntary exit code.
            return {
                "phase": "terminated",
                "exit_code": 1,
                "exit_observed": False,
                "termination": termination,
                "survivors": [],
            }

        # Could not confirm the workload is gone. This is the one outcome that
        # must never be softened, and the caller must not record an exit.
        self._record(
            EventType.TERMINATION_UNVERIFIED,
            action="verify_termination",
            resource=str(pid) if pid is not None else "",
            decision=Decision.KILL,
            risk=Risk.CRITICAL,
            reason=(
                "the protected workload could not be confirmed gone after "
                "termination; this session did NOT verify its containment"
            ),
            metadata={
                "termination": termination,
                "survivors": list(survivors),
                "verify_timeout_seconds": self.FINALIZATION_VERIFY_TIMEOUT,
            },
        )
        if not self._internal_error:
            self._internal_error = (
                "workload termination could not be verified; "
                f"survivors={list(survivors)}"
            )
        return {
            "phase": "termination_unverified",
            "exit_code": 1,
            "exit_observed": False,
            "termination": termination,
            "survivors": list(survivors),
        }

    def _terminate_workload_now(self) -> tuple[dict[str, Any], list[int], bool]:
        """Terminate the live workload and verify it. Returns (detail, survivors, verified).

        Containment units are destroyed through the enforcer, which already
        isolates the network, terminates the whole unit and proves emptiness.
        A merely supervised (V2) workload is terminated through the supervisor's
        own process handle and then *waited on*, which is the deterministic
        primitive for "this child is gone" - no polling loop and no sleep is
        used as synchronisation.
        """
        if self._unit is not None:
            self._destroy_unit(reason="FINALIZATION_WORKLOAD_ALIVE")
            detail = dict(self._containment_termination or {})
            survivors = [int(pid) for pid in (detail.get("survivors") or [])]
            return detail, survivors, bool(detail.get("empty"))

        process = self._process
        if process is None or not process.started:
            return {}, [], True

        try:
            report = process.terminate(grace=self._config.termination_grace)
        except Exception as exc:  # noqa: BLE001 - reported as an unverified kill
            return ({"error": f"{type(exc).__name__}: {exc}"}, [], False)

        detail = report.to_dict()
        failed = [int(pid) for pid in report.failed]

        # ``wait`` is the authoritative confirmation that our own child is
        # gone. A timeout means exactly that: we could not confirm it.
        verified = False
        try:
            process.wait(timeout=self.FINALIZATION_VERIFY_TIMEOUT)
            verified = True
        except subprocess.TimeoutExpired:
            verified = False
        except Exception as exc:  # noqa: BLE001
            detail["wait_error"] = f"{type(exc).__name__}: {exc}"

        if not verified and process.poll() is not None:
            verified = True

        # A tree member the kill could not signal means the tree is not
        # confirmed gone, even when our direct child is.
        if failed:
            verified = False
            for pid in failed:
                if pid not in detail.setdefault("survivors", []):
                    detail["survivors"].append(pid)

        return detail, failed, verified

    def request_shutdown(self, reason: str = "SHUTDOWN_REQUESTED") -> None:
        """Ask for a controlled shutdown. Safe to call from a signal handler.

        This deliberately does almost nothing: it records *why* a stop was
        asked for and wakes the supervision loop, which then performs the
        ordinary kill-and-record path under the normal lock. Doing real work
        (terminating processes, writing the trace) inside a signal handler
        frame is how asynchronous cleanup bugs are born, so it is not done
        here.
        """
        if reason and not self._shutdown_reason:
            self._shutdown_reason = str(reason)
        self._shutdown_requested = True
        self._quit.set()

    def _finalize(self, exit_code: int) -> None:
        # Claim finalisation under the daemon lock before anything else. Every
        # path that could append to the trace takes this lock and checks
        # _shutting_down, so after this returns nothing new can start writing
        # and the seal below cannot be overtaken.
        #
        # The lock is deliberately not held for the rest of the method: the
        # IPC drain joins worker threads, and those workers take this same lock
        # in their disconnect hooks, so holding it across the join would
        # deadlock until the drain deadline expired.
        with self._lock:
            if self._finalised:
                return
            self._finalised = True
            self._shutting_down = True

        watcher = self._watcher
        process = self._process

        # 0. Invariant: no session is finalised or sealed as having exited if
        #    its protected workload is still alive. Finalisation is reached by
        #    paths that did not necessarily observe an exit: a supervisor
        #    exception, a keyboard interrupt, a signal, or a stop request that
        #    could not kill. The liveness of the workload is therefore
        #    established here, and a live workload is terminated and verified
        #    before any lifecycle event is written.
        stop = self._ensure_workload_stopped()
        exit_code = int(stop["exit_code"])
        self._exit_code = exit_code

        # 1. Decide the terminal state.
        if stop["phase"] == "termination_unverified":
            # Protected processes may still be running. That is never a clean
            # or a killed session: it is a failure, and it is stated as one.
            self._state.transition_quiet(
                SessionState.FAILED, "workload termination could not be verified"
            )
        elif watcher is not None and watcher.killed:
            self._state.transition_quiet(SessionState.KILLED, "kill switch engaged")
        elif exit_code == 0 and stop["exit_observed"]:
            self._state.transition_quiet(SessionState.COMPLETED, "process exited cleanly")
        elif exit_code == 0:
            # A clean code that was never observed is not a clean finish.
            self._state.transition_quiet(
                SessionState.FAILED, "no exit status was observed for the workload"
            )
        else:
            self._state.transition_quiet(
                SessionState.FAILED, f"process exited with {exit_code}"
            )

        if watcher is None:
            # Setup failed before a trace existed; nothing to seal. Any
            # container that did start must still be destroyed.
            self._destroy_unit(reason="SETUP_FAILED")
            self._stop_ipc()
            return

        # The workload has exited, or has been terminated and verified gone.
        # Destroy the containment unit and prove it is empty before the trace
        # is sealed, so the final record describes a machine state in which
        # nothing from the sandbox is still running.
        self._destroy_unit(reason="SESSION_ENDED")

        # 2. Stop the IPC writers before anything else is recorded or sealed.
        #    This is the step that makes "no active authoritative writer before
        #    seal" true: the server refuses new requests, waits for in-flight
        #    handlers and for the worker threads that own them to exit, and
        #    reports failure rather than guessing if they will not.
        self._stop_ipc()

        # A client that died without saying goodbye is still a fact about the
        # session. It is recorded after the drain so the disconnect hooks have
        # had their say first, and only a genuinely lost client is flagged.
        self._record_vanished_client()

        # 3. Lifecycle events. ``PROCESS_EXITED`` asserts an observation, so it
        #    is written only when an exit was actually observed. A workload the
        #    supervisor had to terminate gets the termination vocabulary
        #    instead - never a fabricated exit status.
        if stop["exit_observed"]:
            self._record(
                EventType.PROCESS_EXITED,
                action="exit",
                resource=" ".join(process.command) if process is not None else "",
                decision=Decision.KILL if watcher.killed else Decision.ALLOW,
                risk=Risk.CRITICAL if watcher.killed else Risk.NORMAL,
                reason=f"protected process exited with {exit_code}",
                metadata={
                    "exit_code": exit_code,
                    "pid": process.pid if process is not None else None,
                    "duration_seconds": round(process.duration_seconds, 3)
                    if process is not None
                    else 0.0,
                    "exit_observed": True,
                },
            )

        self._record(
            EventType.SESSION_END,
            action="end",
            resource=" ".join(process.command) if process is not None else "",
            decision=Decision.KILL if self.killed else Decision.ALLOW,
            risk=Risk.CRITICAL if (self.killed or stop["phase"] != "already_exited")
            else Risk.NORMAL,
            reason=(
                f"session killed: {watcher.kill_record.reason}"
                if watcher.killed and watcher.kill_record
                else "session finished"
            ),
            metadata={
                "status": self._state.state.value,
                "exit_code": exit_code,
                "exit_observed": stop["exit_observed"],
                "finalization_phase": stop["phase"],
                "workload_survivors": list(stop["survivors"]),
                "duration_seconds": round(
                    (int(self._clock()) - self._started_at), 3
                )
                if self._started_at
                else 0.0,
            },
        )

        # 4. Seal: after this, nothing may be appended. The trace enforces
        #    that itself now, so a straggler write raises rather than quietly
        #    invalidating the declared final hash. The seal event must be
        #    written *before* the seal, so its count describes the trace as it
        #    will be after this event lands rather than one event short.
        self._record(
            EventType.TRACE_SEALED,
            action="seal",
            decision=Decision.ALLOW,
            risk=Risk.NORMAL,
            reason="trace sealed by the external supervisor",
            metadata={"event_count": len(watcher.trace) + 1},
        )
        watcher.seal()

        # 5. Verify the sealed trace before it is written out.
        self._verify_sealed()

        # 6. Persist the authoritative artefacts.
        self._metadata = self._build_metadata(exit_code)
        try:
            self._storage.write_trace(self._session_id, watcher.trace)
            self._storage.write_metadata(self._session_id, self._metadata)
        except Exception as exc:  # noqa: BLE001 - already sealed; keep going
            if not self._internal_error:
                self._internal_error = (
                    f"storage {type(exc).__name__}: {sanitize_text(str(exc), 200)}"
                )

        if self._config.trace_out:
            try:
                watcher.trace.export(self._config.trace_out)
            except Exception as exc:  # noqa: BLE001
                if not self._internal_error:
                    self._internal_error = (
                        f"export {type(exc).__name__}: {sanitize_text(str(exc), 200)}"
                    )

    def _stop_ipc(self) -> None:
        """Drain the IPC writers, or record that they would not drain.

        The supervisor must not seal while a worker could still append, so a
        drain that does not finish is an explicit failure rather than a
        silent proceed. The sealed-append guard in the PoE layer is the
        backstop if this ever fires, but the session is marked failed and the
        condition is written to the trace so it cannot pass unnoticed.
        """
        server = self._server
        if server is None:
            if self._listener is not None:
                try:
                    self._listener.close()
                except Exception:  # noqa: BLE001
                    pass
            return

        timeout = self._config.ipc_drain_timeout
        try:
            self._ipc_drain = server.stop(timeout)
        except IpcDrainTimeout as exc:
            self._ipc_drain_failed = str(exc)
            message = f"IPC drain timeout: {sanitize_text(str(exc), 300)}"
            if not self._internal_error:
                self._internal_error = message
            if not self._state.is_terminal:
                self._state.transition_quiet(SessionState.FAILED, "ipc drain timeout")
            if self._watcher is not None:
                self._record(
                    EventType.IPC_DRAIN_TIMEOUT,
                    action="drain",
                    resource=(
                        self._endpoint.display if self._endpoint else "ipc"
                    ),
                    decision=Decision.KILL,
                    risk=Risk.CRITICAL,
                    reason=message,
                    metadata={
                        "timeout_seconds": timeout,
                        "remaining_workers": list(exc.remaining),
                    },
                )

    def _verify_sealed(self) -> None:
        """Verify the sealed trace and record the outcome.

        Sealing is the moment the audit trail becomes final, so it is also the
        moment to confirm it is sound. Reporting a failed verification here
        means a session cannot quietly ship a trace that does not check out.
        """
        if self._watcher is None:
            return
        result = self._watcher.verify()
        self._sealed_verified = bool(result.valid)
        if not result.valid and not self._internal_error:
            self._internal_error = (
                "sealed trace failed verification: "
                + ", ".join(str(signal) for signal in result.signals)
            )

    def _build_metadata(self, exit_code: int) -> dict[str, Any]:
        watcher = self._watcher
        assert watcher is not None
        verification = watcher.verify()
        kill_record = watcher.kill_record

        payload: dict[str, Any] = {
            "session_id": self._session_id,
            "status": self._state.state.value,
            "exit_code": exit_code,
            "started_at": self._started_at,
            "ended_at": int(self._clock()),
            "duration_seconds": round(
                (int(self._clock()) - self._started_at), 3
            )
            if self._started_at
            else 0.0,
            "state": self._state.to_dict(),
            "killed": watcher.killed,
            "quarantined": watcher.quarantined,
            "command": list(self._config.command),
            "pid": self._process.pid if self._process is not None else None,
            "process": self._process.safe_state() if self._process is not None else None,
            "event_count": len(watcher.trace),
            "final_hash": watcher.trace.declared_final_hash or watcher.trace.final_hash,
            "head_hash": watcher.trace.head_hash,
            "sealed": watcher.trace.sealed,
            "verification": verification.summary(),
            "policy": self._policy.to_dict(),
            "tripwires": [tripwire.to_dict() for tripwire in watcher.tripwires],
            "ipc": {
                "endpoint": self._endpoint.display if self._endpoint else None,
                "family": self._endpoint.family if self._endpoint else None,
                "protocol_version": WATCHER_IPC_VERSION,
                "limits": (self._server.limits.to_dict() if self._server else None),
                "stats": self._server.stats() if self._server else {},
                "clients": self._server.client_contexts() if self._server else [],
            },
            "heartbeat": {
                "enabled": self._config.heartbeat_enabled,
                "interval": self._config.heartbeat_interval,
                "timeout": self._config.heartbeat_timeout,
                "action": self._config.heartbeat_action.value,
                "received": self._heartbeat_count,
                "lost": self._heartbeat_lost,
            },
            "fail_mode": self._config.fail_mode,
            "ipc_lost_action": self._config.ipc_lost_action.value,
            "client_authenticated": self._client_authenticated,
            "supervisor": {
                "termination_grace": self._config.termination_grace,
                "session_timeout": self._config.session_timeout,
            },
            "enforcement": self._enforcement_metadata(),
            "kill": kill_record.to_dict() if kill_record else None,
            "internal_error": self._internal_error,
        }
        return self._scrub(payload)

    def _enforcement_metadata(self) -> dict[str, Any] | None:
        """The V3 section of the authoritative session record."""
        if not self._config.enforced:
            return None

        profile = self._config.containment
        return {
            "mode": self._config.enforcement.value,
            "backend": self._enforcer.backend_name if self._enforcer else None,
            "profile": profile.to_dict() if profile else None,
            "profile_digest": profile.digest() if profile else None,
            "refused": self._enforcement_refused or None,
            "unit": self._unit.to_dict() if self._unit is not None else None,
            "evidence": self._evidence.to_dict() if self._evidence else None,
            "termination": self._containment_termination,
        }

    def stats(self) -> dict[str, Any]:
        """Current, live summary (used by the CLI and tests)."""
        watcher = self._watcher
        return {
            "session_id": self._session_id,
            "state": self._state.state.value,
            "killed": self.killed,
            "quarantined": bool(watcher and watcher.quarantined),
            "event_count": len(watcher.trace) if watcher else 0,
            "final_hash": watcher.trace.final_hash if watcher else None,
            "verification": watcher.verify().summary() if watcher else None,
            "ipc": self._server.stats() if self._server else {},
            "metadata": self._metadata,
        }

    def __repr__(self) -> str:
        return (
            f"<WatcherDaemon session={self._session_id[:8]} "
            f"state={self._state.state.value} killed={self.killed}>"
        )
