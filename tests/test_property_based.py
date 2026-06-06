"""
Property-based tests using Hypothesis.
Tests invariant properties of forensic tool functions and Pydantic models.

All tests that import modules inside the test body use @settings(deadline=None)
to avoid false-positive deadline failures from import overhead.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from src.tools.tool_resolver import find_tool

# ═══════════════════════════════════════════════════════════════════
#  TOOL RESOLUTION PROPERTIES
# ═══════════════════════════════════════════════════════════════════

# find_tool does file-system I/O (shutil.which / PATH lookup),
# so we allow unbounded deadline.


@settings(deadline=None)
@given(st.text())
def test_find_tool_never_crashes(name):
    """find_tool should never raise an exception, regardless of input."""
    result = find_tool(name)
    assert result is None or isinstance(result, str)


@settings(deadline=None)
@given(st.lists(st.text()))
def test_find_tools_batch_never_crashes(names):
    """find_tools batch should never raise."""
    from src.tools.tool_resolver import find_tools

    results = find_tools(*names)
    assert isinstance(results, dict)


# ═══════════════════════════════════════════════════════════════════
#  PATH VALIDATION PROPERTIES
# ═══════════════════════════════════════════════════════════════════


@settings(deadline=None)
@given(st.text())
def test_validate_path_always_returns_string_or_none(path):
    """Path validation should accept any string without crashing."""
    from src.server import _validate_evidence_path

    result = _validate_evidence_path(path)
    assert result is None or isinstance(result, str)


@settings(deadline=None)
@given(st.text())
def test_sanitize_never_crashes(s):
    """Sanitize function should accept any string."""
    from src.server import _sanitize

    result = _sanitize(s)
    assert isinstance(result, str)
    # Output should be printable-safe
    for c in result:
        assert c.isprintable() or c in "\n\r\t"


@settings(deadline=None)
@given(st.text())
def test_truncate_never_crashes(s):
    """Truncate function should accept any string."""
    from src.server import _trunc

    result = _trunc(s)
    assert isinstance(result, str)
    assert len(result) <= 203  # 200 + "..."


@settings(deadline=None)
@given(st.text(min_size=1, max_size=1000), st.integers(min_value=1, max_value=5000))
def test_truncate_shortens_long_strings(s, n):
    """Truncate should never produce strings longer than n+3."""
    from src.server import _trunc

    result = _trunc(s, n)
    assert len(result) <= n + 3


# ═══════════════════════════════════════════════════════════════════
#  EXISTING TOOL-RESULT MODEL PROPERTIES
# ═══════════════════════════════════════════════════════════════════


@settings(deadline=None)
@given(st.text(min_size=1), st.lists(st.integers()))
def test_hash_result_properties(algorithm, values):
    """HashResult model should accept various data shapes."""
    from src.tools.hashing import HashResult

    r = HashResult(
        success=True,
        algorithm=algorithm,
        hash_value="abc123",
        data=[{"algorithm": algorithm, "hash": "abc123", "file": "/test"}],
    )
    assert r.algorithm == algorithm
    assert r.hash_value == "abc123"


@settings(deadline=None)
@given(st.booleans(), st.integers(min_value=0, max_value=10000))
def test_carving_result_properties(success, count):
    """CarvingResult model should accept any file_count."""
    from src.tools.carving import CarvingResult

    r = CarvingResult(success=success, file_count=count)
    assert r.success == success
    assert r.file_count == count


@settings(deadline=None)
@given(st.integers(min_value=0, max_value=100000))
def test_network_result_packet_count(packets):
    """NetworkResult should store any reasonable packet_count."""
    from src.tools.network import NetworkResult

    r = NetworkResult(success=True, packet_count=packets)
    assert r.packet_count == packets


@settings(deadline=None)
@given(st.integers(min_value=0, max_value=50000))
def test_pattern_result_match_count(matches):
    """PatternResult should store any reasonable match_count."""
    from src.tools.patterns import PatternResult

    r = PatternResult(success=True, match_count=matches)
    assert r.match_count == matches


@settings(deadline=None)
@given(st.integers(min_value=0, max_value=1000))
def test_registry_result_key_count(keys):
    """RegistryResult should store any reasonable key_count."""
    from src.tools.registry import RegistryResult

    r = RegistryResult(success=True, key_count=keys)
    assert r.key_count == keys


# ═══════════════════════════════════════════════════════════════════
#  MEMORY RESULT PROPERTIES
# ═══════════════════════════════════════════════════════════════════


@settings(deadline=None)
@given(st.text(min_size=1, max_size=100), st.lists(st.text()))
def test_memory_result_properties(plugin, data_items):
    """MemoryResult should handle various plugin names and data."""
    from src.tools.memory import MemoryResult

    data = [{"note": item} for item in data_items[:50]]
    r = MemoryResult(success=True, plugin=plugin, data=data)
    assert r.plugin == plugin
    assert len(r.data) == len(data)


# ═══════════════════════════════════════════════════════════════════
#  FILESYSTEM RESULT PROPERTIES
# ═══════════════════════════════════════════════════════════════════


@settings(deadline=None)
@given(st.text(min_size=1, max_size=200))
def test_filesystem_result_error_messages(msg):
    """FileSystemResult should store any error string."""
    from src.tools.filesystem import FileSystemResult

    r = FileSystemResult(success=False, error=msg)
    assert r.error == msg


@settings(deadline=None)
@given(st.lists(st.integers(min_value=0, max_value=100000)))
def test_partition_model_properties(slots):
    """Partition model slot values should work."""
    from src.tools.filesystem import Partition

    for i in slots[:10]:
        p = Partition(slot=i, start=0, end=100, length=100, description="test")
        assert p.slot == i


# ═══════════════════════════════════════════════════════════════════
#  TIMELINE RESULT PROPERTIES
# ═══════════════════════════════════════════════════════════════════


@settings(deadline=None)
@given(st.integers(min_value=0, max_value=50000))
def test_timeline_event_count(events):
    """TimelineResult should store event count."""
    from src.tools.timeline import TimelineResult

    r = TimelineResult(success=True, event_count=events)
    assert r.event_count == events


# ═══════════════════════════════════════════════════════════════════
#  NEWLY ADDED: Additional Filesystem Model Properties
# ═══════════════════════════════════════════════════════════════════


@settings(deadline=None)
@given(st.text(min_size=1, max_size=100), st.one_of(st.none(), st.integers(min_value=0)))
def test_file_entry_properties(name, inode_val):
    """FileEntry model should round-trip core fields."""
    from src.tools.filesystem import FileEntry

    entry = FileEntry(name=name, inode=inode_val, file_type="file")
    assert entry.name == name
    assert entry.inode == inode_val
    assert entry.file_type == "file"


@settings(deadline=None)
@given(
    st.integers(min_value=0, max_value=999999),
    st.text(min_size=1, max_size=20),
    st.integers(min_value=0, max_value=65535),
    st.integers(min_value=0, max_value=65535),
    st.integers(min_value=0, max_value=10**12),
    st.integers(min_value=0, max_value=9999),
)
def test_inode_info_properties(inode, mode, uid, gid, size, num_links):
    """InodeInfo model should accept any reasonable inode metadata."""
    from src.tools.filesystem import InodeInfo

    info = InodeInfo(
        inode=inode,
        mode=mode,
        uid=uid,
        gid=gid,
        size=size,
        atime="2024-01-01",
        mtime="2024-01-02",
        ctime="2024-01-03",
        crtime="2024-01-04",
        num_links=num_links,
    )
    assert info.inode == inode
    assert info.uid == uid
    assert info.gid == gid
    assert info.size == size
    assert info.num_links == num_links
    assert info.mode == mode


@settings(deadline=None)
@given(
    st.text(min_size=0, max_size=50),
    st.integers(min_value=0, max_value=65536),
    st.integers(min_value=0, max_value=10**9),
)
def test_fs_stats_properties(fs_type, block_size, block_count):
    """FsStats model stores filesystem metadata properties."""
    from src.tools.filesystem import FsStats

    stats = FsStats(fs_type=fs_type, block_size=block_size, block_count=block_count)
    assert stats.fs_type == fs_type
    assert stats.block_size == block_size
    assert stats.block_count == block_count


# ═══════════════════════════════════════════════════════════════════
#  NEWLY ADDED: Cross-Source Correlation Model Properties
# ═══════════════════════════════════════════════════════════════════


@settings(deadline=None)
@given(
    st.text(min_size=1, max_size=50),
    st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    st.text(min_size=1, max_size=200),
    st.booleans(),
)
def test_discrepancy_properties(d_type, severity, description, ioc):
    """Discrepancy model should accept various finding shapes."""
    from src.tools.correlation import Discrepancy

    d = Discrepancy(type=d_type, severity=severity, description=description, ioc=ioc)
    assert d.type == d_type
    assert d.severity == severity
    assert d.description == description
    assert d.ioc == ioc
    assert d.confidence in ("CONFIRMED", "INFERRED", "UNVERIFIED")


@settings(deadline=None)
@given(st.text(min_size=1, max_size=50), st.booleans(), st.integers(min_value=0, max_value=60000))
def test_analysis_summary_properties(name, success, duration_ms):
    """AnalysisSummary model should store analysis results."""
    from src.tools.correlation import AnalysisSummary

    s = AnalysisSummary(name=name, success=success, duration_ms=duration_ms)
    assert s.name == name
    assert s.success == success
    assert s.duration_ms == duration_ms
    assert s.discrepancy_count == 0
    assert s.error is None


def _make_discrepancies():
    """Builder helper to create Discrepancy instances in strategy context."""
    from src.tools.correlation import Discrepancy

    return st.lists(
        st.builds(
            Discrepancy,
            type=st.text(min_size=1, max_size=20),
            severity=st.sampled_from(["LOW", "MEDIUM", "HIGH"]),
            description=st.text(min_size=1, max_size=100),
        ),
        max_size=3,
    )


@settings(deadline=None)
@given(
    st.text(min_size=1, max_size=100),
    st.text(min_size=1, max_size=100),
    _make_discrepancies(),
)
def test_correlation_report_properties(disk_path, memory_path, discrepancies):
    """CorrelationReport should round-trip top-level fields."""
    from datetime import datetime, timezone

    from src.tools.correlation import CorrelationReport

    now = datetime.now(timezone.utc).isoformat()
    report = CorrelationReport(
        success=True,
        disk_path=disk_path,
        memory_path=memory_path,
        started_at=now,
        completed_at=now,
        duration_ms=1234,
        total_discrepancies=len(discrepancies),
        discrepancies=discrepancies,
    )
    assert report.disk_path == disk_path
    assert report.memory_path == memory_path
    assert report.total_discrepancies == len(discrepancies)
    assert report.success is True


# ═══════════════════════════════════════════════════════════════════
#  NEWLY ADDED: Shared Model Properties (src/models.py)
# ═══════════════════════════════════════════════════════════════════


@settings(deadline=None)
@given(st.text(min_size=1, max_size=100), st.one_of(st.none(), st.integers(min_value=0)))
def test_file_system_entry_properties(name, inode_val):
    """FileSystemEntry model should accept various metadata shapes."""
    from src.models import FileSystemEntry

    e = FileSystemEntry(name=name, inode=inode_val, file_type="file")
    assert e.name == name
    assert e.inode == inode_val
    assert e.file_type == "file"


@settings(deadline=None)
@given(
    st.text(min_size=1, max_size=50),
    st.text(min_size=1, max_size=200),
    st.sampled_from(["CONFIRMED", "INFERRED", "UNVERIFIED"]),
    st.text(min_size=1, max_size=50),
    st.text(min_size=1, max_size=50),
)
def test_finding_properties(id_val, description, confidence, artifact_type, tool_used):
    """Finding model should store forensic findings."""
    from src.models import Finding

    f = Finding(
        id=id_val,
        description=description,
        confidence=confidence,
        artifact_type=artifact_type,
        tool_used=tool_used,
    )
    assert f.id == id_val
    assert f.description == description
    assert f.confidence == confidence
    assert f.artifact_type == artifact_type
    assert f.tool_used == tool_used


@settings(deadline=None)
@given(
    st.text(min_size=1, max_size=50),
    st.booleans(),
    st.integers(min_value=0, max_value=60000),
)
def test_tool_execution_properties(tool_name, success, duration_ms):
    """ToolExecution model should record tool audit data."""
    from src.models import ToolExecution

    te = ToolExecution(tool=tool_name, success=success, duration_ms=duration_ms)
    assert te.tool == tool_name
    assert te.success == success
    assert te.duration_ms == duration_ms


@settings(deadline=None)
@given(
    st.text(min_size=1, max_size=50),
    st.integers(min_value=0, max_value=100),
    st.integers(min_value=0, max_value=100),
    st.integers(min_value=0, max_value=100),
    st.integers(min_value=0, max_value=600000),
)
def test_audit_report_properties(session_id, total, successful, failed, total_duration):
    """AuditReport model should aggregate execution statistics."""
    from src.models import AuditReport

    report = AuditReport(
        session_id=session_id,
        total_calls=total,
        successful_calls=successful,
        failed_calls=failed,
        total_duration_ms=total_duration,
    )
    assert report.session_id == session_id
    assert report.total_calls == total
    assert report.successful_calls == successful
    assert report.failed_calls == failed
    assert report.total_duration_ms == total_duration
