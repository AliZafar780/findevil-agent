#!/bin/bash
set -euo pipefail

echo "╔══════════════════════════════════════════════════╗"
echo "║     FIND EVIL! — Autonomous DFIR Agent          ║"
echo "║     Powered by Groq AI + SIFT Workstation       ║"
echo "╚══════════════════════════════════════════════════╝"

# ── Configuration ─────────────────────────────────────────────────
EVIDENCE_PATH="${1:-/evidence/cases/test.raw}"
TASK="${2:-Investigate this forensic image for signs of compromise}"
RESULTS_DIR="/results/$(date +%Y%m%d_%H%M%S)"

export EVIDENCE_ROOT="/evidence"
export RESULTS_ROOT="$RESULTS_DIR"
export GROQ_API_KEY="${GROQ_API_KEY:-}"

mkdir -p "$RESULTS_DIR"

echo ""
echo "  Evidence: $EVIDENCE_PATH"
echo "  Task:     $TASK"
echo "  Results:  $RESULTS_DIR"
echo ""

# ── Check Groq API Key ────────────────────────────────────────────
if [ -z "$GROQ_API_KEY" ]; then
    if [ -f .env ]; then
        source .env
    fi
    if [ -z "$GROQ_API_KEY" ]; then
        echo "[!] WARNING: GROQ_API_KEY not set."
        echo "    AI-powered report generation will be disabled."
        echo "    Set it: export GROQ_API_KEY='gsk_...'"
        echo ""
    fi
fi

# ── Validate evidence ─────────────────────────────────────────────
if [ ! -f "$EVIDENCE_PATH" ]; then
    echo "[!] Evidence file not found: $EVIDENCE_PATH"
    echo "    Create a test image first:"
    echo "    truncate -s 50M /evidence/cases/test.raw"
    echo "    mkfs.ext2 -F /evidence/cases/test.raw"
    exit 1
fi

# ── Source virtual environment ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

if [ -d "venv" ]; then
    source venv/bin/activate
fi

# ── Start MCP Server ──────────────────────────────────────────────
echo "[*] Starting MCP server..."
python -m src.server &
SERVER_PID=$!
sleep 2

# ── Run full agent workflow ───────────────────────────────────────
echo "[*] Running Groq-powered DFIR agent workflow..."
python3 << PYSCRIPT 2>&1 | tee "$RESULTS_DIR/agent_output.log"
import asyncio, json, os, sys
sys.path.insert(0, ".")

os.environ["EVIDENCE_ROOT"] = "$EVIDENCE_ROOT"
os.environ["RESULTS_ROOT"] = "$RESULTS_DIR"

async def main():
    from src.agent.loop import SimpleMCPClient, DFIRWorkflow, ToolCall
    from src.agent.groq_client import GroqDFIRClient
    
    groq = GroqDFIRClient()
    client = SimpleMCPClient()
    await client.start()
    
    workflow = DFIRWorkflow(client, groq_client=groq)
    workflow._evidence_path = "$EVIDENCE_PATH"
    
    print("=" * 60)
    print("Starting DFIR Analysis")
    print("=" * 60)
    
    # Run workflow phases
    phases = {
        "initial_triage": ["list_evidence", "verify_hash", "fs_filesystem_info"],
        "filesystem_analysis": ["fs_list_files", "fs_file_metadata", "fs_extract_file"],
        "artifact_extraction": ["carve_files", "scan_yara"],
    }
    
    for phase_name, tools in phases.items():
        print(f"\n--- Phase: {phase_name} ---")
        for tool in tools:
            workflow.state.iteration += 1
            tc = ToolCall(tool, workflow._build_args(tool), workflow.state.iteration)
            try:
                result = await client.call_tool(tool, tc.arguments)
                parsed = json.loads(result) if isinstance(result, str) else result
                tc.success = parsed.get("success", False)
                tc.duration_ms = parsed.get("duration_ms", 0)
                if tc.success:
                    workflow._extract_findings(tool, parsed)
                    print(f"  ✅ {tool}")
                else:
                    print(f"  ⚠️ {tool}: {parsed.get('error', 'unknown')}")
            except Exception as e:
                tc.error = str(e)
                print(f"  ❌ {tool}: {e}")
            workflow.state.record_call(tc)
    
    # Generate Groq report
    print(f"\n--- Generating AI Report ---")
    findings = [f for f in workflow.state.findings if f.get("type") != "case_info"]
    
    try:
        if groq.api_key:
            report = groq.generate_report(findings, [t.to_dict() for t in workflow.state.tool_calls])
            print("✅ Groq AI report generated")
            result_data = {"report": report, "success": True}
        else:
            raise ValueError("No API key")
    except Exception as e:
        print(f"⚠️ Groq report failed, using fallback: {e}")
        result_data = {"report": workflow._generate_narrative(), "success": True}
    
    result_data["summary"] = workflow.state.get_summary()
    result_data["findings"] = workflow.state.findings
    result_data["tool_calls"] = [t.to_dict() for t in workflow.state.tool_calls]
    
    with open("$RESULTS_DIR/agent_result.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"\n{'=' * 60}")
    print(f"Analysis complete!")
    print(f"Tool calls: {result_data['summary']['tool_calls']}")
    print(f"Findings:   {result_data['summary']['findings']}")
    print(f"Duration:   {result_data['summary']['elapsed_seconds']}s")
    print(f"{'=' * 60}")
    
    await client.stop()

asyncio.run(main())
PYSCRIPT

# ── Cleanup ────────────────────────────────────────────────────────
kill $SERVER_PID 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║     RESULTS                                     ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Results:  $RESULTS_DIR                        ║"
echo "║  Log:      $RESULTS_DIR/agent_output.log        ║"
echo "║  Report:   $RESULTS_DIR/agent_result.json       ║"
echo "╚══════════════════════════════════════════════════╝"
