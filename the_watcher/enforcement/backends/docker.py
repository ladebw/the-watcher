"""Docker / OCI container enforcement backend.

Present for completeness and for hosts that have a container runtime. On this
development host Docker is **not** installed (``watcher doctor`` says so, and
:func:`select_backend` will not select it), so this backend is *unverified
here*. It is written conservatively and refuses every configuration it cannot
guarantee, which is the only safe posture for untested security code.

Hardening applied to each unit:

``--read-only``                 read-only container root filesystem
``--no-new-privileges``         cannot gain privileges through setuid binaries
``--cap-drop=ALL``              no Linux capabilities
``--security-opt=no-new-privileges``
``--user <uid>:<gid>``          non-root inside the container
``--network none|host``         no egress by default
``--pids-limit``                fork-bomb ceiling
``--memory`` / ``--cpus``       resource ceilings
``--tmpfs /tmp``                small writable scratch
``--mount ...,readonly``        bind mounts are read-only unless explicitly writable

Refused outright: ``--privileged``, ``--cap-add`` (beyond the profile's explicit
allow-list), any bind of the container runtime socket, and any host namespace
sharing (``--pid=host``, ``--net=host`` unless ``network=open``).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid

from ...exceptions import ContainmentRefused, ContainmentStartError
from ...runtime import LocalProcess
from ..base import (
    ContainmentState,
    ContainmentUnit,
    EnforcementEvidence,
    Enforcer,
    SandboxSpec,
    TerminationOutcome,
)
from ..declared import require_honourable
from ..procfs import read_cgroup

__all__ = ["DockerEnforcer"]

DEFAULT_IMAGE = "python:3.12-slim"


class DockerEnforcer(Enforcer):
    """Containment through a container runtime CLI."""

    backend_name = "docker"

    def __init__(self, capabilities=None, runtime_root: "str | None" = None) -> None:
        super().__init__(capabilities)
        self._runtime_root = runtime_root
        self._binary = "docker"

    # -- preparation -----------------------------------------------------

    def _run(self, args: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
        try:
            completed = subprocess.run(
                [self._binary, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return 127, "", f"{type(exc).__name__}: {exc}"
        return completed.returncode, completed.stdout, completed.stderr

    def prepare(self, profile, spec: "SandboxSpec | None" = None) -> None:
        self.require_available()
        profile.validate()
        # This backend applies a much smaller part of a profile than the
        # namespace backend does. A setting it cannot honour must stop the
        # session here rather than appear in the digest as enforced.
        require_honourable(
            profile,
            self.backend_name,
            allow_reduced_protection=profile.allow_reduced_protection,
        )

        if profile.allow_privileged:
            raise ContainmentRefused("privileged containers are never allowed")
        if profile.allow_docker_socket:
            raise ContainmentRefused(
                "mounting the container runtime socket is never allowed"
            )
        if profile.network.value == "restricted":
            raise ContainmentRefused(
                "network=restricted is not implemented for the container "
                "backend; it would require programming host firewall rules"
            )

        code, _, err = self._run(["version", "--format", "{{.Server.Version}}"])
        if code != 0:
            raise ContainmentStartError(
                f"the container runtime is not usable: {err.strip()[:200]}"
            )

        if spec is not None:
            image = os.environ.get("WATCHER_CONTAINER_IMAGE", DEFAULT_IMAGE)
            if not image or any(ch in image for ch in " \t\n;&|$`"):
                raise ContainmentRefused(f"refusing unsafe image reference: {image!r}")

    # -- launch ----------------------------------------------------------

    def launch(self, spec: SandboxSpec) -> ContainmentUnit:
        unit_key = spec.unit_key or uuid.uuid4().hex
        name = f"watcher-{unit_key}"[:63]
        image = os.environ.get("WATCHER_CONTAINER_IMAGE", DEFAULT_IMAGE)
        profile = spec.profile
        filesystem = profile.filesystem

        args: list[str] = [
            "run",
            "--rm",
            "--name",
            name,
            "--read-only",
            "--no-new-privileges",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={max(1, profile.processes.max_processes)}",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,size={filesystem.tmpfs_size_mb}m",
        ]

        if profile.resources.memory_mb:
            args += ["--memory", f"{profile.resources.memory_mb}m"]
        if profile.resources.cpus:
            args += ["--cpus", str(profile.resources.cpus)]
        if profile.resources.max_file_size_mb:
            # ulimit fsize is in 512-byte blocks.
            args += [
                "--ulimit",
                f"fsize={profile.resources.max_file_size_mb * 2048}",
                "--ulimit",
                f"nofile={max(64, profile.processes.max_open_files)}",
            ]

        args += ["--network", "none" if profile.network.value == "none" else "host"]

        args += [
            "--mount",
            f"type=bind,src={os.path.realpath(spec.workspace_host)},"
            f"dst={spec.workspace_inner}",
        ]
        if spec.control_dir_host:
            args += [
                "--mount",
                "type=bind,"
                f"src={os.path.realpath(spec.control_dir_host)},"
                f"dst={spec.control_dir_inner},readonly",
            ]

        # Run as the invoking user so files written into the workspace stay
        # owned by the operator rather than root.
        args += ["--user", f"{os.getuid()}:{os.getgid()}"]
        args += ["-w", spec.cwd_inner or spec.workspace_inner]

        for key, value in spec.environment.items():
            args += ["-e", f"{key}={value}"]

        args.append(image)
        args += list(spec.command)

        process = LocalProcess([self._binary, *args], env=dict(os.environ))
        pid = process.start()

        unit = ContainmentUnit(
            unit_key=unit_key,
            backend=self.backend_name,
            profile_digest=spec.profile.digest(),
            process=process,
            host_pid=pid,
            state=ContainmentState.STARTING,
            control_dir_inner=spec.control_dir_inner if spec.control_dir_host else None,
            workspace_inner=spec.workspace_inner,
            started_at=int(time.time()),
            metadata={
                "container": name,
                "image": image,
                "network_mode": profile.network.value,
            },
        )

        # Wait for the container to exist before inspecting it.
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            code, out, _ = self._run(
                ["inspect", "--format", "{{.Id}}", name], timeout=10.0
            )
            if code == 0 and out.strip():
                unit.metadata["container_id"] = out.strip()
                unit.state = ContainmentState.RUNNING
                return unit
            if process.pid and not process.alive:
                break
            time.sleep(0.1)

        self._force_remove(name)
        unit.state = ContainmentState.FAILED
        raise ContainmentStartError(f"container {name} did not start")

    # -- inspection ------------------------------------------------------

    def inspect(self, unit: ContainmentUnit) -> EnforcementEvidence:
        name = unit.metadata.get("container", "")
        code, out, err = self._run(["inspect", name], timeout=15.0)
        if code != 0:
            return EnforcementEvidence(
                backend=self.backend_name,
                verified=False,
                problems=(f"cannot inspect container {name}: {err.strip()[:200]}",),
            )

        try:
            payload = json.loads(out)[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            return EnforcementEvidence(
                backend=self.backend_name,
                verified=False,
                problems=(f"unparsable inspect output for {name}",),
            )

        host_config = payload.get("HostConfig") or {}
        config = payload.get("Config") or {}
        state = payload.get("State") or {}

        problems: list[str] = []
        if not host_config.get("ReadonlyRootfs"):
            problems.append("the container root filesystem is not read-only")
        if not any(
            "no-new-privileges" in str(opt)
            for opt in (host_config.get("SecurityOpt") or [])
        ):
            problems.append("no-new-privileges is not set")
        if host_config.get("Privileged"):
            problems.append("the container is privileged")
        if (host_config.get("CapAdd") or []):
            problems.append(f"capabilities were added: {host_config.get('CapAdd')}")
        if not host_config.get("CapDrop") or "ALL" not in [
            str(c).upper() for c in host_config.get("CapDrop") or []
        ]:
            problems.append("not all capabilities were dropped")
        network_mode = host_config.get("NetworkMode")
        if unit.metadata.get("network_mode", "none") == "none" and network_mode != "none":
            problems.append(f"expected network mode none, found {network_mode!r}")
        for mount in payload.get("Mounts") or []:
            destination = str(mount.get("Destination", ""))
            source = str(mount.get("Source", ""))
            if "docker.sock" in source or "podman.sock" in source:
                problems.append(f"the container runtime socket is mounted at {destination}")
        if state.get("Paused"):
            problems.append("the container is paused")

        user = str(config.get("User") or "")
        uid_inside: "int | None" = None
        if user:
            try:
                uid_inside = int(user.split(":")[0])
            except ValueError:
                uid_inside = None
        if uid_inside == 0:
            problems.append("the container runs as root inside")

        return EnforcementEvidence(
            backend=self.backend_name,
            verified=not problems,
            uid_on_host=os.getuid(),
            uid_inside_namespace=uid_inside,
            capabilities_effective=",".join(host_config.get("CapAdd") or []) or "(dropped ALL)",
            capabilities_on_host="",
            no_new_privs=any(
                "no-new-privileges" in str(opt)
                for opt in (host_config.get("SecurityOpt") or [])
            ),
            seccomp_mode=None,
            landlock_abi=None,
            namespaces={},
            cgroup=read_cgroup(unit.host_pid or 0),
            read_only_root=bool(host_config.get("ReadonlyRootfs")),
            network_isolated=network_mode == "none",
            network_interfaces=("none" if network_mode == "none" else str(network_mode),),
            process_count=int(state.get("Pid", 0) > 0),
            problems=tuple(problems),
        )

    # -- isolation and termination ---------------------------------------

    def isolate_network(self, unit: ContainmentUnit) -> tuple[bool, str]:
        name = unit.metadata.get("container", "")
        if unit.metadata.get("network_mode", "none") == "none":
            return True, f"{name} runs with --network none"
        code, _, err = self._run(["pause", name], timeout=15.0)
        if code != 0:
            return False, f"could not pause {name}: {err.strip()[:120]}"
        return True, f"{name} paused"

    def terminate(self, unit: ContainmentUnit, grace: float = 2.0) -> TerminationOutcome:
        started = time.perf_counter()
        name = unit.metadata.get("container", "")
        unit.state = ContainmentState.TERMINATING

        self._run(["kill", "--signal", "SIGTERM", name], timeout=10.0)
        deadline = time.monotonic() + max(0.1, grace)
        while time.monotonic() < deadline:
            code, out, _ = self._run(
                ["inspect", "--format", "{{.State.Running}}", name], timeout=5.0
            )
            if code != 0 or out.strip().lower() == "false":
                break
            time.sleep(0.05)

        self._run(["kill", "--signal", "SIGKILL", name], timeout=10.0)
        self._run(["rm", "-f", name], timeout=15.0)

        if unit.process is not None and unit.process.started:
            try:
                unit.process.terminate_tree(grace=0.5)
            except Exception:  # noqa: BLE001 - best effort during teardown
                pass

        ok, survivors = self.verify_empty(unit)
        unit.state = ContainmentState.TERMINATED if ok else ContainmentState.KILL_FAILED
        outcome = TerminationOutcome(
            state=unit.state,
            method="docker",
            terminated=(),
            remaining=tuple(survivors),
            forced=True,
            network_isolated=bool(unit.metadata.get("network_isolated")),
            duration_seconds=time.perf_counter() - started,
        )
        unit.termination = outcome
        return outcome

    def verify_empty(self, unit: ContainmentUnit) -> tuple[bool, list[int]]:
        name = unit.metadata.get("container", "")
        code, out, _ = self._run(["ps", "-a", "--filter", f"name=^{name}$", "-q"])
        if code != 0:
            return False, []
        return (not out.strip()), []

    def _force_remove(self, name: str) -> None:
        self._run(["rm", "-f", name], timeout=15.0)

    # -- introspection ---------------------------------------------------

    def describe(self) -> str:
        """A one-line description for the audit trail."""
        code, out, err = self._run(["version", "--format", "{{.Server.Version}}"])
        if code != 0:
            return f"docker unavailable: {err.strip()[:120]}"
        return f"docker server {out.strip()}"
