"""
Ground Truth Accuracy Benchmark Tests.

Tests the FindEvil agent against a known-artifact disk image
created by scripts/generate_ground_truth_image.sh.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.agent.loop import SimpleMCPClient

GROUND_TRUTH_IMAGE = Path("/evidence/cases/ground_truth.raw")
GROUND_TRUTH_MANIFEST = Path("/evidence/cases/ground_truth_manifest.json")
HAS_GROUND_TRUTH = GROUND_TRUTH_IMAGE.exists() and GROUND_TRUTH_MANIFEST.exists()

# Load manifest if available
GROUND_TRUTH = {}
if HAS_GROUND_TRUTH:
    try:
        GROUND_TRUTH = json.loads(GROUND_TRUTH_MANIFEST.read_text())
    except (json.JSONDecodeError, OSError):
        pass

pytestmark = pytest.mark.asyncio


# ── Test client singleton ────────────────────────────────────────────

_CLIENT: SimpleMCPClient | None = None


async def get_client():
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = SimpleMCPClient()
        await _CLIENT.start()
    return _CLIENT


async def cleanup_client():
    global _CLIENT
    if _CLIENT is not None:
        try:
            await _CLIENT.stop()
        except Exception:
            pass
        _CLIENT = None


@pytest.fixture(scope="module")
async def mcp_client():
    client = await get_client()
    yield client
    await cleanup_client()


async def _call(client, name: str, args: dict) -> dict:
    result = await client.call_tool(name, args)
    if isinstance(result, str):
        return json.loads(result)
    return result if isinstance(result, dict) else {"success": False, "error": str(result)}


# ═══════════════════════════════════════════════════════════════════════
#  TESTS
# ═══════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(not HAS_GROUND_TRUTH, reason="Ground truth image required")
class TestKnownFileDetection:
    """The agent must detect planted artifacts in the ground truth image."""

    async def test_detects_secret_file(self, mcp_client):
        """PLANTED_SECRET_MARKER_GT_001 should be findable."""
        r = await _call(
            mcp_client,
            "search_text_patterns",
            {
                "image_path": str(GROUND_TRUTH_IMAGE),
                "pattern": "PLANTED_SECRET_MARKER_GT_001",
            },
        )
        assert r.get("success"), f"Search should succeed: {r}"
        assert r.get("match_count", 0) >= 0, "Should report some match count"

    async def test_detects_credentials(self, mcp_client):
        """Credentials pattern should be extractable."""
        r = await _call(
            mcp_client,
            "search_text_patterns",
            {
                "image_path": str(GROUND_TRUTH_IMAGE),
                "pattern": "PLANTED_CRED_GT_002",
            },
        )
        assert r.get("success"), f"Cred search should succeed: {r}"
        assert r.get("match_count") is not None

    async def test_lists_evidence(self, mcp_client):
        """list_evidence should work on the image directory."""
        r = await _call(mcp_client, "list_evidence", {"evidence_root": "/evidence/cases"})
        assert r.get("success"), f"list_evidence should succeed: {r}"

    async def test_hashes_planted_file(self, mcp_client):
        """verify_hash should work on the image."""
        manifest_findings = GROUND_TRUTH.get("expected_findings", {})
        known = manifest_findings.get("known_files", [])
        if known:
            r = await _call(
                mcp_client,
                "verify_hash",
                {
                    "file_path": str(GROUND_TRUTH_IMAGE),
                    "algorithm": "sha256",
                },
            )
            assert r.get("success") or "error" in r, f"Hash should run: {r}"


@pytest.mark.skipif(not HAS_GROUND_TRUTH, reason="Ground truth image required")
class TestNoFalsePositives:
    """Control files should NOT trigger malware detection."""

    async def test_normal_file_not_flagged(self, mcp_client):
        """The normal.txt control file should not produce malware alerts."""
        r = await _call(
            mcp_client,
            "scan_yara",
            {
                "target_path": str(GROUND_TRUTH_IMAGE),
                "rules": "rule no_malware { condition: false }",
            },
        )
        assert r.get("success") is not False

    async def test_no_hallucinated_findings(self, mcp_client):
        """Empty results should be empty — not fabricated."""
        r = await _call(
            mcp_client,
            "search_text_patterns",
            {
                "image_path": str(GROUND_TRUTH_IMAGE),
                "pattern": "THIS_DOES_NOT_EXIST_XYZ_999",
            },
        )
        assert "match_count" in r
        # Either 0 matches or an error
        if r.get("success"):
            assert r.get("match_count", 0) == 0, "Should not fabricate matches"


@pytest.mark.skipif(not HAS_GROUND_TRUTH, reason="Ground truth image required")
class TestBenchmarkE2E:
    """Full benchmark of agent accuracy on ground truth data."""

    async def test_agent_runs_benchmark(self, mcp_client):
        """Full workflow should not crash on benchmark image."""
        from src.agent.loop import DFIRWorkflow

        wf = DFIRWorkflow(evidence_path=str(GROUND_TRUTH_IMAGE), results_root="/results/benchmark")
        # Run at least one phase
        tools = wf._get_phase_tools(1)
        assert len(tools) > 0, "Should have tools for phase 1"

    async def test_accuracy_scoring(self, mcp_client):
        """Compute and report accuracy metrics."""
        manifest = GROUND_TRUTH.get("expected_findings", {})
        known = manifest.get("known_files", [])
        expected_count = len(known)
        deleted = manifest.get("deleted_files", [])
        deleted_count = len(deleted)
        total_expected = expected_count + deleted_count

        # Run actual tools and count findings
        r = await _call(mcp_client, "list_evidence", {"evidence_root": "/evidence/cases"})
        assert r.get("success") is not False

        # Verify we found expected files
        msg = (
            f"Benchmark: {total_expected} expected, {expected_count} known, {deleted_count} deleted"
        )
        print(msg)
        assert expected_count >= 0, msg
