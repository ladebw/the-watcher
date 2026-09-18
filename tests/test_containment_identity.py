"""Phase 0 Blocker B: containment-unit identity and sound emptiness proofs.

The defects these tests exist for:

1. ``NamespaceEnforcer.inspect`` assigned the result of a fresh ``/proc`` read
   straight onto ``unit.namespaces``. When the workload had already exited that
   read produced an empty set, so the unit's identity was erased by the very
   event the identity is needed for.
2. ``verify_empty``/``_unit_processes`` keyed on a *single* namespace inode and
   returned "no survivors" when there was no namespace to look for - a fail-open
   answer that reported a sandbox as empty precisely when it could not tell.
3. A process that created a child namespace (nested user or PID namespace) no
   longer carries the unit's inode values and was therefore invisible.

The properties asserted here:

* an identity recorded at launch is never erased by a later observation;
* an unknown identity fails closed, never "empty";
* a descendant that changes namespaces is still found, via ancestry;
* a recycled pid is not mistaken for a unit ancestor.
"""

from __future__ import annotations

import os
import sys

import pytest


from the_watcher.enforcement.base import (
    ContainmentIdentity,
    ContainmentUnit,
    SurvivorScan,
)
from the_watcher.enforcement.procfs import NamespaceIds, ProcRecord

UNIT_USER_NS = "user:[4026532000]"
UNIT_PID_NS = "pid:[4026532001]"
HOST_USER_NS = "user:[4026531837]"
HOST_PID_NS = "pid:[4026531836]"


def _enforcer():
    from the_watcher.enforcement.backends.namespaces import NamespaceEnforcer

    return NamespaceEnforcer(capabilities=None, runtime_root=None)


def _unit(**kwargs) -> ContainmentUnit:
    defaults = dict(
        unit_key="unit0001",
        backend="namespaces",
        profile_digest="0" * 64,
        host_pid=os.getpid(),
    )
    defaults.update(kwargs)
    return ContainmentUnit(**defaults)


def _identity(**kwargs) -> ContainmentIdentity:
    defaults = dict(
        launcher_pid=5000,
        launcher_start_time=100,
        sandbox_pid=5001,
        sandbox_start_time=101,
        namespaces=NamespaceIds(values={"user": UNIT_USER_NS, "pid": UNIT_PID_NS}),
        cgroup="/user.slice/watcher/unit0001",
        recorded_at=1_760_000_000,
    )
    defaults.update(kwargs)
    return ContainmentIdentity(**defaults)


def _record(pid, ppid, *, user_ns=HOST_USER_NS, pid_ns=HOST_PID_NS, state="S",
            start=100, cgroup=None) -> ProcRecord:
    return ProcRecord(
        pid=pid,
        ppid=ppid,
        state=state,
        start_time=start,
        user_ns=user_ns,
        pid_ns=pid_ns,
        cgroup=cgroup,
    )


# ---------------------------------------------------------------------------
# 1. Identity is not erasable
# ---------------------------------------------------------------------------


def test_identity_is_preferred_over_a_blanked_namespaces_field():
    """A blank read must not change what the unit is identified by.

    This reproduces the old failure exactly: the observed namespaces are
    replaced by an empty set after the workload exits.
    """
    unit = _unit(identity=_identity(), namespaces=NamespaceIds(values={}))

    assert unit.user_namespace == UNIT_USER_NS

    # Even if the mutable field is blanked (as ``inspect`` used to do), the
    # launch-time identity still answers.
    unit.namespaces = NamespaceIds(values={})
    assert unit.user_namespace == UNIT_USER_NS


def test_identity_falls_back_when_no_identity_was_recorded():
    unit = _unit(namespaces=NamespaceIds(values={"user": UNIT_USER_NS}))
    assert unit.user_namespace == UNIT_USER_NS
    unit.namespaces = NamespaceIds(values={})
    assert unit.user_namespace is None


def test_identity_serialises_without_erasing_information():
    identity = _identity()
    payload = identity.to_dict()
    assert payload["known"] is True
    assert payload["namespaces"]["user"] == UNIT_USER_NS
    assert payload["launcher_pid"] == 5000


# ---------------------------------------------------------------------------
# 2. Unknown identity fails closed
# ---------------------------------------------------------------------------


def test_unknown_identity_fails_closed():
    """No identity must never be reported as an empty sandbox."""
    unit = _unit(namespaces=NamespaceIds(values={}))
    empty, survivors = _enforcer().verify_empty(unit)

    assert empty is False, "an unverifiable unit was reported as empty"
    assert survivors == []
    scan = unit.metadata["survivor_scan"]
    assert scan["identity_known"] is False
    assert "cannot be verified empty" in scan["note"]


def test_base_enforcer_fails_closed_without_a_namespace():
    """The abstract default must fail closed too."""
    unit = _unit(namespaces=NamespaceIds(values={}))
    scan = _enforcer().scan_survivors(unit)
    assert isinstance(scan, SurvivorScan)
    assert scan.empty is False
    assert scan.identity_known is False


# ---------------------------------------------------------------------------
# 3. Layered scan: nested namespaces and recycled pids
# ---------------------------------------------------------------------------


def test_ancestry_layer_catches_a_nested_namespace_descendant(monkeypatch):
    """The adversarial escape: a descendant that changes its namespaces.

    The descendant carries neither the unit's user-namespace inode nor its
    PID-namespace inode, because it created child namespaces of both. A
    single-inode check cannot see it; the ancestry layer can.
    """
    import the_watcher.enforcement.backends.namespaces as ns_module

    unit = _unit(identity=_identity())

    records = [
        # The sandbox init is already gone (this is the case that used to make
        # the unit look empty) ...
        _record(6000, 1, user_ns=HOST_USER_NS, pid_ns=HOST_PID_NS),
        # ... but the launcher is still alive and is the supervisor's own child.
        _record(5000, 1, start=100),
        # The evasive descendant: new user ns AND new pid ns, still a child of
        # the launcher's subtree.
        _record(5002, 5000, user_ns="user:[4026532999]", pid_ns="pid:[4026532998]"),
    ]
    monkeypatch.setattr(ns_module, "snapshot", lambda exclude=None: records)

    scan = _enforcer().scan_survivors(unit)

    assert scan.empty is False, "the nested-namespace descendant was invisible"
    assert 5002 in scan.survivors
    assert scan.layers["ancestry"]["pids"] == [5002]
    assert 5000 in scan.survivors, "the live launcher is part of the unit"
    assert scan.layers["pid_namespace"]["pids"] == []
    assert scan.layers["user_namespace"]["pids"] == []


def test_pid_namespace_layer_catches_a_process_that_changed_user_namespace(monkeypatch):
    """A descendant in a child user namespace is still in the unit's PID namespace."""
    import the_watcher.enforcement.backends.namespaces as ns_module

    unit = _unit(identity=_identity())
    records = [
        _record(7000, 1, user_ns="user:[4026532999]", pid_ns=UNIT_PID_NS),
    ]
    monkeypatch.setattr(ns_module, "snapshot", lambda exclude=None: records)

    scan = _enforcer().scan_survivors(unit)

    assert scan.empty is False
    assert scan.survivors == (7000,)
    assert scan.layers["pid_namespace"]["pids"] == [7000]


def test_recycled_pid_is_not_treated_as_a_unit_ancestor(monkeypatch):
    """A pid whose start time differs is a different process, not a survivor."""
    import the_watcher.enforcement.backends.namespaces as ns_module

    unit = _unit(identity=_identity())
    records = [
        # Same pid as the launcher, but started at a different time.
        _record(5000, 1, start=999),
        _record(8000, 5000, start=1000),
    ]
    monkeypatch.setattr(ns_module, "snapshot", lambda exclude=None: records)

    scan = _enforcer().scan_survivors(unit)

    assert scan.empty is True, "a recycled pid produced a phantom survivor"
    assert scan.survivors == ()
    assert scan.layers["ancestry"]["live_roots"] == []


def test_cgroup_layer_is_used_when_recorded(monkeypatch):
    import the_watcher.enforcement.backends.namespaces as ns_module

    unit = _unit(identity=_identity())
    records = [
        _record(9000, 1, cgroup="/user.slice/watcher/unit0001"),
        _record(9001, 1, cgroup="/user.slice/other"),
    ]
    monkeypatch.setattr(ns_module, "snapshot", lambda exclude=None: records)

    scan = _enforcer().scan_survivors(unit)

    assert scan.survivors == (9000,)
    assert scan.layers["cgroup"]["pids"] == [9000]


def test_zombies_are_not_reported_as_survivors(monkeypatch):
    """A zombie cannot execute; counting it would be a false alarm."""
    import the_watcher.enforcement.backends.namespaces as ns_module

    unit = _unit(identity=_identity())
    records = [
        _record(9100, 1, pid_ns=UNIT_PID_NS, state="Z"),
    ]
    monkeypatch.setattr(ns_module, "snapshot", lambda exclude=None: records)

    scan = _enforcer().scan_survivors(unit)

    assert scan.empty is True
    assert scan.layers["pid_namespace"]["pids"] == []


def test_scan_reports_every_layer_it_consulted(monkeypatch):
    """The scan must be auditable: the trace records what was checked."""
    import the_watcher.enforcement.backends.namespaces as ns_module

    unit = _unit(identity=_identity())
    monkeypatch.setattr(ns_module, "snapshot", lambda exclude=None: [])

    scan = _enforcer().scan_survivors(unit)

    assert scan.empty is True
    assert scan.identity_known is True
    assert set(scan.layers) == {
        "pid_namespace",
        "user_namespace",
        "ancestry",
        "cgroup",
    }
    payload = scan.to_dict()
    assert payload["empty"] is True
    assert "pid_namespace" in payload["layers"]


def test_snapshot_excludes_the_supervisor_itself(monkeypatch):
    """The caller's own pid must not be a candidate survivor."""
    import the_watcher.enforcement.backends.namespaces as ns_module

    captured = {}

    def fake_snapshot(exclude=None):
        captured["exclude"] = set(exclude or set())
        return []

    monkeypatch.setattr(ns_module, "snapshot", fake_snapshot)
    _enforcer().scan_survivors(_unit(identity=_identity()))

    assert os.getpid() in captured["exclude"]


def test_descendants_of_is_pid_reuse_guarded():
    """A pure-logic check of the ancestry walk's reuse guard."""
    from the_watcher.enforcement.procfs import descendants_of

    records = [
        _record(100, 1, start=10),
        _record(101, 100, start=11),
        _record(102, 101, start=12),
        _record(200, 1, start=20),
    ]

    assert descendants_of({100: 10}, records) == [101, 102]
    # Wrong start time: pid 100 is not the process we recorded.
    assert descendants_of({100: 999}, records) == []
    assert descendants_of({}, records) == []


# ---------------------------------------------------------------------------
# 4. Real containment (Linux + a host that can enforce)
# ---------------------------------------------------------------------------


def test_verify_empty_on_a_real_unit_is_not_erased_by_inspect(monkeypatch):
    """A synthetic end-to-end check of inspect-then-verify ordering.

    ``inspect`` on a live pid must populate the identity; a later ``verify_empty``
    against synthetic records that *do* contain a unit process must still find
    it. This is the ordering the old code got wrong.
    """
    import the_watcher.enforcement.backends.namespaces as ns_module
    from the_watcher.enforcement.procfs import NamespaceIds as _NS

    unit = _unit(
        identity=_identity(
            namespaces=_NS(values={"user": UNIT_USER_NS, "pid": UNIT_PID_NS})
        )
    )

    # Simulate the post-inspect state the old code produced: namespaces blanked.
    unit.namespaces = _NS(values={})

    monkeypatch.setattr(
        ns_module,
        "snapshot",
        lambda exclude=None: [_record(9500, 1, pid_ns=UNIT_PID_NS)],
    )

    empty, survivors = _enforcer().verify_empty(unit)
    assert empty is False
    assert survivors == [9500]


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="containment-unit identity is exercised against /proc on Linux",
)
def test_real_snapshot_reads_this_process():
    """The snapshot must be able to describe the test process itself."""
    from the_watcher.enforcement.procfs import snapshot

    records = {record.pid: record for record in snapshot()}
    mine = records.get(os.getpid())
    assert mine is not None, "the snapshot did not include the current process"
    assert mine.live is True
    assert mine.start_time is not None
    assert mine.user_ns is not None
    assert mine.pid_ns is not None
    assert mine.ppid > 0
