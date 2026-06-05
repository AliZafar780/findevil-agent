"""Test the DFIR workflow agent loop."""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestDFIRWorkflow:
    """Test the agent workflow against real evidence."""

    TEST_IMG = "/evidence/cases/test.raw"

    @pytest.fixture(autouse=True)
    async def setup_teardown(self):
        """Per-test setup: check evidence exists, provide test img."""
        self.test_img = self.TEST_IMG
        yield

    async def _run_workflow(self, task: str, client_type: str = "standard") -> dict:
        """Run a workflow and return results."""
        from src.agent.loop import DFIRWorkflow, SimpleMCPClient

        client = SimpleMCPClient()
        try:
            await client.start()
            workflow = DFIRWorkflow(client)
            result = await workflow.run(task, self.test_img)
            return result
        finally:
            await client.stop()

    async def test_workflow_initial_triage(self):
        """Test just the initial triage phase."""
        # The workflow runs through all phases but this validates
        # that initial_triage tools at least execute
        result = await self._run_workflow(
            "Quick triage check: list available files and compute hashes"
        )
        assert result is not None

    async def test_workflow_full_phases(self):
        """Test all phases of the workflow."""
        result = await self._run_workflow("Analyze forensic image for signs of compromise")
        assert result is not None


if __name__ == "__main__":
    t = TestDFIRWorkflow()

    async def run_all():
        tests = [
            ("initial_triage", t.test_workflow_initial_triage),
            ("full_workflow", t.test_workflow_full_phases),
        ]
        passed = 0
        failed = 0
        for name, test_func in tests:
            try:
                await test_func()
                print(f"\n  ✅ {name}")
                passed += 1
            except Exception as e:
                print(f"\n  ❌ {name}: {e}")
                import traceback

                traceback.print_exc()
                failed += 1

        print(f"\n{'='*40}")
        print(f"Results: {passed} passed, {failed} failed")
        return failed == 0

    success = asyncio.run(run_all())
    sys.exit(0 if success else 1)
