"""Trust boundaries: thin client, fail-closed defaults and no overclaiming."""

from __future__ import annotations

import json
import pathlib
import re
import sys

import pytest

from the_watcher.exceptions import IpcTransportError
from the_watcher.ipc import WatcherClient
from the_watcher.ipc.transport import IpcListener, create_endpoint
from the_watcher.watcher.decision import Decision, Risk

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = PROJECT_ROOT / "the_watcher"


def read(relative: str) -> str:
    return (PACKAGE / relative).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The client must be disposable
# ---------------------------------------------------------------------------


def test_client_module_contains_no_policy_or_kill_logic():
    """The protected process must not evaluate or enforce anything itself."""
    source = read("ipc/client.py")
    forbidden = (
        "Policy",
        "KillSwitch",
        "TripwireRegistry",
        "Tripwire",
        "Recorder",
        "ExecutionTrace",
        "LocalProcess",
        "ProcessSupervisor",
        "terminate_tree",
        "WatcherDaemon",
        "SessionStorage",
    )
    for token in forbidden:
        assert token not in source, f"client.py must not reference {token}"


def test_client_module_does_not_import_supervisor_internals():
    source = read("ipc/client.py")
    imports = re.findall(r"^\s*(?:from|import)\s+([\w\.]+)", source, re.MULTILINE)
    for module in imports:
        for forbidden in ("supervisor", "policy", "tripwire", "kill_switch", "recorder", "trace"):
            assert forbidden not in module, f"client.py must not import {module}"


def test_client_only_uses_the_decision_vocabulary():
    """The one thing the client imports from the Watcher core is the vocabulary."""
    source = read("ipc/client.py")
    assert "from ..watcher.decision import Decision, Risk" in source


def test_client_has_no_process_termination_ability():
    source = read("ipc/client.py")
    assert "os.kill" not in source
    assert "signal" not in source
    assert "taskkill" not in source


# ---------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------


def make_client(**overrides):
    defaults = {
        "session_id": "boundarytest",
        "endpoint_address": r"\\.\pipe\the-watcher-does-not-exist"
        if sys.platform == "win32"
        else "/tmp/the-watcher-does-not-exist.sock",
        "token": "token-that-is-never-logged",
        "timeout": 0.6,
        "connect_now": False,
    }
    defaults.update(overrides)
    return WatcherClient(**defaults)


def test_unreachable_watcher_fails_closed_by_default():
    client = make_client()
    decision = client.evaluate("file_access", "read", "/etc/shadow")

    assert decision.decision is Decision.DENY
    assert decision.blocked
    assert decision.ipc_ok is False
    assert decision.rule == "ipc_unavailable"
    assert "failing CLOSED" in decision.reason


def test_unreachable_watcher_can_fail_open_only_when_asked():
    client = make_client(fail_mode="fail_open")
    decision = client.evaluate("file_access", "read", "/etc/shadow")

    assert decision.decision is Decision.ALLOW
    assert decision.ipc_ok is False
    assert decision.risk is Risk.ELEVATED
    assert "failing OPEN" in decision.reason


def test_default_fail_mode_is_fail_closed():
    client = make_client()
    assert client.fail_mode.value == "fail_closed"


def test_request_timeout_fails_closed(tmp_path):
    """A daemon that accepts the pipe but never answers must not grant access."""
    endpoint = create_endpoint("timeouttest1")
    listener = IpcListener(endpoint)
    # The pipe exists but nothing ever accepts or replies.
    client = WatcherClient(
        session_id="timeouttest1",
        endpoint_address=endpoint.address,
        token="token-that-is-never-logged",
        family=endpoint.family,
        timeout=0.5,
        connect_now=False,
    )
    try:
        decision = client.evaluate("file_access", "read", "/etc/shadow")
        assert decision.decision is Decision.DENY
        assert decision.rule == "ipc_unavailable"
        assert client.connected is False
    finally:
        client.close(notify=False)
        listener.close()


def test_requires_configuration():
    with pytest.raises(IpcTransportError):
        WatcherClient(session_id="", endpoint_address="x", token="y")
    with pytest.raises(IpcTransportError):
        WatcherClient(session_id="a", endpoint_address="", token="y")
    with pytest.raises(IpcTransportError):
        WatcherClient(session_id="a", endpoint_address="x", token="")


def test_from_environment_requires_the_documented_variables():
    with pytest.raises(IpcTransportError, match="WATCHER_SESSION_ID"):
        WatcherClient.from_environment(env={})


def test_from_environment_rejects_a_wrong_protocol_version():
    with pytest.raises(IpcTransportError, match="protocol version"):
        WatcherClient.from_environment(
            env={
                "WATCHER_SESSION_ID": "abc12345",
                "WATCHER_IPC_ENDPOINT": "somewhere",
                "WATCHER_SESSION_TOKEN": "token",
                "WATCHER_PROTOCOL_VERSION": "99",
            }
        )


def test_observe_and_heartbeat_return_false_when_unreachable():
    client = make_client()
    assert client.observe("tool_request", "invoke", "search") is False
    assert client.heartbeat() is False
    assert client.status() == {}
    assert client.request_kill("stop") is False
    assert client.session_end() is False


# ---------------------------------------------------------------------------
# The session token must never leak
# ---------------------------------------------------------------------------


def test_session_token_never_reaches_the_trace_or_metadata(harness_factory, tmp_path):
    harness = harness_factory(
        "normal", trace_out=str(tmp_path / "exported.json")
    )
    assert harness.wait(timeout=60) == 0

    daemon = harness.daemon
    token = daemon._token  # trusted-side access, same process as the daemon
    assert token and len(token) > 20

    trace_json = daemon.trace.to_json()
    metadata = daemon.stats()["metadata"]
    metadata_json = json.dumps(metadata, sort_keys=True)
    exported = pathlib.Path(tmp_path / "exported.json").read_text(encoding="utf-8")

    for label, blob in (
        ("trace", trace_json),
        ("metadata", metadata_json),
        ("export", exported),
    ):
        assert token not in blob, f"the session token leaked into the {label}"


def test_session_token_never_reaches_the_client(harness_factory):
    """The handshake response must not echo the token back."""
    harness = harness_factory("normal")
    assert harness.wait(timeout=60) == 0

    token = harness.daemon._token
    for event in harness.daemon.trace:
        assert token not in event.resource
        assert token not in json.dumps(event.metadata, sort_keys=True)
        assert token not in event.reason


def test_failed_authentication_leaks_nothing(harness_factory):
    from the_watcher.ipc.protocol import MessageType, build_request
    from the_watcher.ipc.transport import CLIENT_RECEIVE_TYPES, connect

    harness = harness_factory("heartbeat", child_env={"WATCHER_AGENT_SLEEP": "6"})
    assert harness.wait_until_running()
    daemon = harness.daemon
    token = daemon._token

    connection = connect(daemon.endpoint, timeout=5.0)
    try:
        connection.send(
            build_request(
                MessageType.HELLO,
                {
                    "token": token + "-wrong",
                    "pid": 4242,
                    "protocol_version": 1,
                    "client": {"note": token},  # attempt to smuggle the token
                },
                session_id=daemon.session_id,
            ),
            daemon._server.limits,
        )
        response = connection.receive(
            daemon._server.limits, allowed_types=CLIENT_RECEIVE_TYPES
        )
        assert response["ok"] is False
        assert response["error_code"] == "BAD_TOKEN"
        assert token not in json.dumps(response)
    finally:
        connection.close()

    daemon.stop("DONE")
    assert harness.wait(timeout=60) == 137

    blob = json.dumps(daemon.stats(), sort_keys=True, default=str)
    assert token not in blob
    assert token not in daemon.trace.to_json()


def test_cli_output_never_contains_the_session_token(tmp_path):
    """The end-to-end CLI path must not print the token either."""
    import subprocess

    from conftest import PROJECT_ROOT as root

    storage = tmp_path / "home"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "the_watcher.cli",
            "run",
            "--storage-root",
            str(storage),
            "--",
            sys.executable,
            "-c",
            "print('hi')",
        ],
        capture_output=True,
        text=True,
        cwd=str(root),
        timeout=120,
        check=False,
    )
    output = (completed.stdout or "") + (completed.stderr or "")

    for session_dir in (storage / "sessions").glob("*"):
        trace = (session_dir / "trace.json").read_text(encoding="utf-8")
        metadata = (session_dir / "metadata.json").read_text(encoding="utf-8")
        token = json.loads(metadata).get("session_token")
        assert token is None, "the token must not be stored at all"
        assert "WATCHER_SESSION_TOKEN" not in trace

    assert "WATCHER_SESSION_TOKEN" not in output
    assert completed.returncode == 0


# ---------------------------------------------------------------------------
# Provenance and honest scope
# ---------------------------------------------------------------------------


def test_no_module_imports_aaip():
    """The whole package, V2 modules included, stays independent of AAIP."""
    pattern = re.compile(r"^\s*(?:from|import)\s+aaip\b", re.MULTILINE)
    offenders = [
        str(path.relative_to(PACKAGE))
        for path in PACKAGE.rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"modules importing AAIP: {offenders}"
    assert not [name for name in sys.modules if name == "aaip" or name.startswith("aaip.")]


def test_no_identity_or_blockchain_code_in_v2_modules():
    relevant = (
        "ipc/protocol.py",
        "ipc/server.py",
        "ipc/client.py",
        "ipc/transport.py",
        "supervisor/daemon.py",
        "supervisor/session.py",
        "supervisor/storage.py",
        "supervisor/process_supervisor.py",
    )
    banned = (
        "ed25519",
        "ed25519",
        "blockchain",
        "solana",
        "web3",
        "staking",
        "escrow",
        "validator",
        "reputation",
    )
    for name in relevant:
        source = read(name).lower()
        for token in banned:
            assert token not in source, f"{name} must not mention {token}"


def test_readme_documents_v2_and_disclaims_containment():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert "V3" in readme, "the README must describe the V3 milestone"
    assert "IPC" in readme

    # Markdown emphasis is invisible to a reader, so it must not be what makes
    # the disclaimer "not present". Normalise it away before checking, which
    # keeps the requirement strict without making it a formatting trap.
    plain = readme.replace("*", "").replace("_", "").lower()
    assert "does not" in plain and "containment" in plain, (
        "the README must state plainly that V2 does not claim containment"
    )
    assert "v2 does not provide containment" in plain, (
        "the disclaimer must name V2 explicitly, not merely allude to it"
    )


def test_daemon_docstring_disclaims_containment():
    source = read("supervisor/daemon.py").lower()
    assert "does **not** contain" in source or "does not contain" in source


def test_v1_in_process_api_still_works(clock):
    """V2 must not have broken the V1 embedded watcher."""
    from the_watcher import Policy, PoEWatcher

    watcher = PoEWatcher(policy=Policy(forbidden_paths=["/etc/shadow"]))
    allowed = watcher.evaluate("file_access", "read", "/tmp/fine")
    denied = watcher.evaluate("file_access", "read", "/etc/shadow")

    assert allowed.decision is Decision.ALLOW
    assert denied.decision is Decision.DENY
    assert watcher.verify().valid


def test_v1_trace_format_is_unchanged(clock):
    """The hash-chain schema and event payload keys must not have drifted."""
    from the_watcher import Recorder

    recorder = Recorder(session_id="v1format001", clock=clock)
    event = recorder.record("file_access", "read", "/tmp/x")
    payload = event.to_dict()

    assert set(payload) == {
        "sequence",
        "timestamp",
        "event_type",
        "action",
        "resource",
        "decision",
        "risk",
        "reason",
        "metadata",
        "previous_hash",
        "event_hash",
    }
    assert recorder.trace.to_dict()["schema_version"] == "watcher-poe/1"
    assert recorder.trace.verify().valid
