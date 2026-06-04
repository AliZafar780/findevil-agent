# Demo Video Script — Find Evil! Agent

> **Duration:** ≤5 minutes
> **Required elements:** Live terminal, audio narration, ≥1 self-correction sequence

---

## SCRIPT

### [0:00-0:30] THE PROBLEM — "AI attacks in minutes, defenders in minutes too?"

**Visual:** Split screen — left shows attacker timeline graphic, right shows blank terminal

**Narration:**
"AI-powered adversaries can go from initial access to full domain control in under 8 minutes. MIT research shows AI-driven attack workflows running 47x faster than human operators. Meanwhile, incident responders are still typing commands. The gap is the most dangerous problem in cybersecurity. We built the solution."

### [0:30-1:00] OUR SOLUTION — "Meet FindEvil Agent"

**Visual:** Architecture diagram overlay → terminal window

**Narration:**
"We built FindEvil Agent — an autonomous DFIR analysis system that combines a custom MCP server with SIFT Workstation's 200+ tools. The agent thinks like a senior analyst: methodical, self-correcting, and fully auditable."

### [1:00-2:30] LIVE DEMO — "Watch it work"

**Visual:** Terminal with agent running against forensic image

```bash
# Start the MCP server
$ . venv/bin/activate && python -m src.server

# In another terminal, run the agent
$ python -c "
import asyncio
from agent.loop import SimpleMCPClient, DFIRWorkflow

async def main():
    client = SimpleMCPClient()
    await client.start()
    wf = DFIRWorkflow(client, 'Senior DFIR Analyst')
    result = await wf.run(
        'Investigate /evidence/cases/forensic.raw for signs of compromise',
        '/evidence/cases/forensic.raw'
    )
    print(result['report'])
    print(f'Done: {len(result[\"findings\"])} findings in {len(result[\"tool_calls\"])} tool calls')
    await client.stop()

asyncio.run(main())
"
```

**Narration (while agent runs):**
"The agent starts by scanning the partition table to understand the evidence structure. Then verifies integrity with SHA256. Then examines the filesystem. Each step builds on the last — just like a human analyst would."

**On-screen text during execution:**
- `[fs_partition_scan] → 6 partitions found`
- `[verify_hash] → SHA256: 436d...b242`
- `[fs_filesystem_info] → ext2 filesystem`
- `[fs_list_files] → 3 files found`

### [2:30-3:00] SELF-CORRECTION — "Recovering from failure"

**Visual:** Agent encounters error → attempts different approach → succeeds

**Narration (key moment — REQUIRED for submission):**
"Here's where the agent proves it's not just a script. When the primary tool fails — maybe a corrupt partition or timeout — the agent doesn't crash. It logs the error, tries a fallback tool, and continues. This self-correction loop is the difference between a smart script and an autonomous analyst."

**On-screen text:**
- `⚠️ carve_files failed: corrupt image sector`
- `↪ Trying alternative: extract_features`
- `✅ Found 127 feature artifacts`

### [3:00-4:00] RESULTS — "Structured findings"

**Visual:** Agent output showing structured report

```json
{
  "findings": [
    {
      "type": "partition_table",
      "description": "Found 6 partitions",
      "confidence": "CONFIRMED"
    },
    {
      "type": "file_listing",
      "description": "hello.txt contains suspicious strings",
      "confidence": "CONFIRMED",
      "traced_to": {
        "tool": "fs_extract_file",
        "timestamp": "2026-06-03T23:30:00Z"
      }
    }
  ]
}
```

**Narration:**
"Every finding includes confidence levels and a complete audit trail — traceable back to the specific tool execution that produced it. Judges can verify every claim."

### [4:00-4:30] ARCHITECTURE — "How it's built"

**Visual:** Architecture diagram with trust boundaries highlighted

**Narration:**
"Our key innovation: architectural guardrails instead of prompt-based. The MCP server enforces read-only access to evidence. Typed functions prevent destructive commands. The output directory is restricted to `/results`. Every path is validated against the evidence root. This is the difference between a demo and a production-ready tool."

### [4:30-5:00] CALL TO ACTION — "Build with us"

**Visual:** GitHub repo URL, final agent output

**Narration:**
"FindEvil Agent is open source at [github.com/yourname/findevil-agent]. It takes 5 minutes to deploy on any SIFT Workstation. We invite the community to build on this — add new tools, improve self-correction, expand to memory forensics. Together, we can close the speed gap."

---

## RECORDING CHECKLIST

- [ ] Terminal font: 14pt+ monospace, light background
- [ ] No sensitive info visible in terminal
- [ ] Audio: clear narration, no background noise
- [ ] Self-correction sequence visible (timestamp 2:30-3:00)
- [ ] Total runtime under 5:00
- [ ] Video format: MP4, H.264, 1080p
- [ ] Upload to Devpost + YouTube (unlisted)
