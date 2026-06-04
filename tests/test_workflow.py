"""Test the DFIR workflow agent loop."""
import asyncio
import json
import sys
from pathlib import Path


class TestDFIRWorkflow:
    """Test the agent workflow against real evidence."""

    @classmethod
    def setup_class(cls):
        cls.test_img = "/evidence/cases/forensic.raw"

    async def test_workflow_initial_triage(self):
        """Test just the initial triage phase (uses run() with limited scope)."""
        from agent.loop import SimpleMCPClient, DFIRWorkflow

        client = SimpleMCPClient()
        try:
            await client.start()

            workflow = DFIRWorkflow(client, "Test system prompt")
            # Use the full run() method but with a simple prompt to test the flow
            result = await workflow.run(
                "Quick triage check: list available files and compute hashes",
                self.test_img,
            )

            print(f"\nResult success: {result['success']}")
            print(f"\nFindings ({len(result.get('findings', []))}):")
            for f in result.get('findings', []):
                print(f"  - {f.get('type', 'unknown')}: {f.get('description', '')[:100]} [{f.get('confidence', 'N/A')}]")

            assert result["success"] is True
            assert len(result.get("tool_calls", [])) > 0

        finally:
            await client.stop()

    async def test_workflow_full_phases(self):
        """Test all phases of the workflow."""
        from agent.loop import SimpleMCPClient, DFIRWorkflow

        client = SimpleMCPClient()
        try:
            await client.start()

            workflow = DFIRWorkflow(client, "DFIR Analyst")
            result = await workflow.run(
                "Analyze forensic image for signs of compromise",
                self.test_img,
            )

            print(f"\nFinal report: {json.dumps(result['summary'], indent=2)}")
            print(f"\nNarrative:\n{result['report'][:500]}...")
            print(f"\nTotal calls: {len(result['tool_calls'])}")

            assert result["success"] is True
            assert len(result["tool_calls"]) > 0
            assert len(result["findings"]) > 0

        finally:
            await client.stop()


if __name__ == "__main__":
    t = TestDFIRWorkflow()
    t.setup_class()

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
