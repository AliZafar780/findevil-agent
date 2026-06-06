"""
Property-based tests using Hypothesis.
Tests invariant properties of forensic tool functions.
"""

from hypothesis import given, strategies as st, settings
from src.tools.tool_resolver import find_tool

# ── Tool Resolution Properties ──────────────────────────────────


@given(st.text())
def test_find_tool_never_crashes(name):
    """find_tool should never raise an exception, regardless of input."""
    result = find_tool(name)
    assert result is None or isinstance(result, str)


@given(st.lists(st.text()))
def test_find_tools_batch_never_crashes(names):
    """find_tools batch should never raise."""
    from src.tools.tool_resolver import find_tools

    results = find_tools(*names)
    assert isinstance(results, dict)


# ── Path Validation Properties ─────────────────────────────────


@settings(deadline=None)
@given(st.text())
def test_validate_path_always_returns_string_or_none(path):
    """Path validation should accept any string without crashing."""
    from src.server import _validate_evidence_path

    result = _validate_evidence_path(path)
    assert result is None or isinstance(result, str)


@given(st.text())
def test_sanitize_never_crashes(s):
    """Sanitize function should accept any string."""
    from src.server import _sanitize

    result = _sanitize(s)
    assert isinstance(result, str)
    # Output should be printable-safe
    for c in result:
        assert c.isprintable() or c in "\n\r\t"


@given(st.text())
def test_truncate_never_crashes(s):
    """Truncate function should accept any string."""
    from src.server import _trunc

    result = _trunc(s)
    assert isinstance(result, str)
    assert len(result) <= 203  # 200 + "..."


@given(st.text(min_size=1, max_size=1000), st.integers(min_value=1, max_value=5000))
def test_truncate_shortens_long_strings(s, n):
    """Truncate should never produce strings longer than n+3."""
    from src.server import _trunc

    result = _trunc(s, n)
    assert len(result) <= n + 3


# ── Pydantic Model Properties ──────────────────────────────────


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


@given(st.booleans(), st.integers(min_value=0, max_value=10000))
def test_carving_result_properties(success, count):
    """CarvingResult model should accept any file_count."""
    from src.tools.carving import CarvingResult

    r = CarvingResult(success=success, file_count=count)
    assert r.success == success
    assert r.file_count == count


@given(st.integers(min_value=0, max_value=100000))
def test_network_result_packet_count(packets):
    """NetworkResult should store any reasonable packet_count."""
    from src.tools.network import NetworkResult

    r = NetworkResult(success=True, packet_count=packets)
    assert r.packet_count == packets


@given(st.integers(min_value=0, max_value=50000))
def test_pattern_result_match_count(matches):
    """PatternResult should store any reasonable match_count."""
    from src.tools.patterns import PatternResult

    r = PatternResult(success=True, match_count=matches)
    assert r.match_count == matches


@given(st.integers(min_value=0, max_value=1000))
def test_registry_result_key_count(keys):
    """RegistryResult should store any reasonable key_count."""
    from src.tools.registry import RegistryResult

    r = RegistryResult(success=True, key_count=keys)
    assert r.key_count == keys


# ── Memory Result Properties ──────────────────────────────────


@given(st.text(min_size=1, max_size=100), st.lists(st.text()))
def test_memory_result_properties(plugin, data_items):
    """MemoryResult should handle various plugin names and data."""
    from src.tools.memory import MemoryResult

    data = [{"note": item} for item in data_items[:50]]
    r = MemoryResult(success=True, plugin=plugin, data=data)
    assert r.plugin == plugin
    assert len(r.data) == len(data)


# ── Filesystem Result Properties ──────────────────────────────


@given(st.text(min_size=1, max_size=200))
def test_filesystem_result_error_messages(msg):
    """FileSystemResult should store any error string."""
    from src.tools.filesystem import FileSystemResult

    r = FileSystemResult(success=False, error=msg)
    assert r.error == msg


@given(st.lists(st.integers(min_value=0, max_value=100000)))
def test_partition_model_properties(slots):
    """Partition model slot values should work."""
    from src.tools.filesystem import Partition

    for i in slots[:10]:
        p = Partition(slot=i, start=0, end=100, length=100, description="test")
        assert p.slot == i


# ── Timeline Result Properties ────────────────────────────────


@given(st.integers(min_value=0, max_value=50000))
def test_timeline_event_count(events):
    """TimelineResult should store event count."""
    from src.tools.timeline import TimelineResult

    r = TimelineResult(success=True, event_count=events)
    assert r.event_count == events
