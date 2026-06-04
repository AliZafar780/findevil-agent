# FIND EVIL! — Strategic Recommendations

> **Battle-tested recommendations for maximizing your hackathon score**
> Based on deep analysis of judges, criteria, competition, and our arsenal

---

## 🏆 OVERALL STRATEGY

### Primary Recommendation: **HYBRID APPROACH (Plan A)**

Combine **Custom MCP Server** (Approach 2) for architectural soundness with **Direct Agent Extension** (Approach 1) for rapid prototyping.

**Why this wins:**
1. Judges explicitly call Custom MCP Server *"the most sound architecture in the evaluation"*
2. Self-correction loop satisfies Criterion 1 (tiebreaker)
3. Audit trail logging satisfies Criterion 5
4. Complete submission package satisfies Criterion 6

**ROI Estimate:** Custom MCP Server = 40% of total score potential, Agent Loop = 25%, Submission Package = 20%, Depth = 15%

---

## 🔟 TOP 10 RECOMMENDATIONS

### 1. ARCHITECTURAL GUARDRAILS > PROMPT-BASED — Always

The judges are **explicit**: they want to see security boundaries enforced at the architecture level, not just in prompts.

| Approach | Judge Rating | Risk |
|----------|:----------:|:----:|
| Type-safe MCP functions | ✅ EXCELLENT | Zero modification risk |
| Shell command wrapper | ⚠️ ACCEPTABLE | Agent could craft malicious commands |
| Prompt-based restrictions | ❌ WEAK | Model can ignore |

**Action:** In your architecture diagram and accuracy report, clearly mark which guardrails are architectural vs prompt-based. Document what happens when prompt-based ones fail.

### 2. SELF-CORRECTION IS NOT OPTIONAL — It's mandatory

The demo video **must** show at least one self-correction sequence. This is explicitly required.

**Best self-correction examples for demo:**
1. Tool times out → agent narrows scope → retries → succeeds
2. Tool returns empty → agent tries alternative tool → finds results
3. Conflicting findings → agent runs third validation tool → resolves

### 3. BE HONEST IN THE ACCURACY REPORT — It's signal, not weakness

The judges said: *"If you found failure modes, document them. That's signal, not weakness."*

**Structure your accuracy report:**
```
## Accuracy Report

### Test Dataset: [name/source]

### Confirmed Correct Findings (n)
- [Finding 1] — verified by [method]
- [Finding 2] — verified by [method]

### False Positives (n)
- [FP 1] — what we thought, what it actually was, root cause

### Missed / False Negatives (n)
- [Miss 1] — what we missed, why, how we'd catch it next time

### Hallucinated Claims (n)
- [Hallucination 1] — what the model claimed, what was actually true

### Evidence Integrity Testing
- [ ] Tested read-only enforcement: PASS/FAIL
- [ ] Tested prompt-based guardrails: PASS/FAIL (if prompt-based, document bypass attempts)
- [ ] Tested path traversal prevention: PASS/FAIL
```

### 4. FOCUS DEPTH — Not breadth

Criterion 3: *"Depth on fewer types beats shallow coverage of many."*

**Optimal focus areas:**
1. **Disk forensics** (fls, icat, istat, mmls) — The foundation
2. **Memory forensics** (Volatility 3) — High-impact findings
3. **Timeline analysis** (Plaso) — The narrative backbone

**Skip (unless time permits):**
- Network forensics (complex, niche)
- Mobile forensics (specialized, limited tools)
- Registry deep-dives (Windows-specific)

### 5. TRACEABILITY IS THE DIFFERENCE — Between 2nd and 1st

Criterion 5: *"Can judges trace any finding back to the specific tool execution that produced it?"*

**Implementation:**
```python
{
  "finding": "Suspicious process: malware.exe",
  "traced_to": {
    "tool": "mem_analyze",
    "arguments": {"memory_path": "/evidence/case1.mem", "plugin": "windows.pslist.PsList"},
    "timestamp": "2026-06-10T14:30:22.123Z",
    "raw_output_snippet": "malware.exe  1234  5678  ...",
    "iteration": 7
  }
}
```

Every finding in your output must link back to a specific log entry.

### 6. PICK THE RIGHT TEAM SIZE

| Team Size | Best For | Risks |
|-----------|----------|-------|
| **Solo** | Full control, no coordination overhead | Can be overwhelmed |
| **2-3** | 🏆 **SWEET SPOT** — One builds MCP, one builds agent, one tests/docs | Need clear division |
| **4-5** | Maximum parallel output | Coordination overhead, communication failures |

**Recommended split for 3-person team:**
- **Person A** (MCP server + SIFT tool wrappers) — days 1-6
- **Person B** (Agent loop + self-correction + prompts) — days 3-8
- **Person C** (Testing + accuracy + submission package) — days 5-12

### 7. START WITH KNOWN-GOOD DATA

Don't wait for the perfect dataset. Use these immediately:
- **NIST CFReDS:** https://cfreds-archives.nist.gov/ — Standard forensic test images
- **SANS DFIR Challenges:** Past Find Evil datasets
- **DFIR Challenge Repos:** GitHub community challenges
- **DIY:** Create a small test image with known artifacts (e.g., `dd if=/dev/zero of=test.img bs=1M count=100` + formatted with known files)

### 8. PIPELINE AUTOMATION — Parallel execution where possible

Protocol SIFT runs tools serially. **Your agent should parallelize independent operations.**

```python
# Example parallel dispatch
import asyncio

async def parallel_triage(image_path):
    """Run independent triage steps in parallel."""
    tasks = {
        "partitions": filesystem.scan_partitions(image_path),
        "strings": filesystem.extract_strings(image_path),
        "hash": hashing.compute_hash(image_path, "sha256"),
    }
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    return dict(zip(tasks.keys(), results))
```

### 9. DEMO VIDEO SCRIPT — Structure for maximum impact

```
[0:00-0:30] PROBLEM: "AI attackers move in seconds. Defenders still type commands."
[0:30-1:00] SOLUTION: "We built FindEvil Agent — an autonomous DFIR analyst."
[1:00-1:30] SETUP: Show SIFT Workstation + evidence loading
[1:30-3:00] LIVE EXECUTION: Agent triages disk image
  - Runs partition scan → lists files → builds timeline
  - Finds suspicious artifacts → deep dives
[3:00-3:30] SELF-CORRECTION: Tool fails → agent recovers → demonstrates different approach
[3:30-4:00] RESULTS: Agent presents findings summary
[4:00-4:30] ARCHITECTURE: Quick diagram walkthrough (trust boundaries highlighted)
[4:30-5:00] CLOSING: Repo, try it yourself, thank judges
```

### 10. SUBMISSION QUALITY CHECKLIST — Final review

Before submitting, verify:

```
ALL 8 COMPONENTS PRESENT?
[ ] 1. GitHub repo — public, MIT license, clean README
[ ] 2. Demo video — ≤5 min, terminal capture, audio, self-correction visible
[ ] 3. Architecture diagram — trust boundaries MARKED, guardrail types LABELED
[ ] 4. Project description — all sections filled, specific about design decisions
[ ] 5. Dataset documentation — source links, test protocol, results
[ ] 6. Accuracy report — honest, includes failures, evidence integrity tested
[ ] 7. Try-it-out — step-by-step, tested on clean environment
[ ] 8. Execution logs — JSON, timestamped, traceable

QUALITY CHECK
[ ] Self-correction visible in video? (REQUIRED)
[ ] Architectural guardrails documented? (REQUIRED for high score)
[ ] Each finding traceable to tool execution? (Criterion 5)
[ ] Accuracy report includes failures? (Signal, not weakness)
[ ] Evidence integrity tested and results documented?
[ ] README can be followed by any SIFT user?
```

---

## 🚀 QUICK START ACTION PLAN (Today)

### What to do RIGHT NOW:

```
HOUR 1: Setup
[ ] docker pull sansdfir/sift
[ ] git clone https://github.com/teamdfir/protocol-sift
[ ] mkdir -p ~/findevil-agent && cd ~/findevil-agent
[ ] python3 -m venv venv && source venv/bin/activate

HOUR 2-3: Core MCP Server
[ ] Copy src/server.py from this MemoryGraph
[ ] Copy src/security.py — set up evidence guard
[ ] Copy src/audit.py — set up logging
[ ] Verify: python -m src.server starts successfully

HOUR 4: First Tools
[ ] Copy src/tools/filesystem.py — fls, icat, mmls
[ ] Test: run a tool against a test image
[ ] Test: path validation blocks outside /evidence

HOUR 5-6: Agent Loop
[ ] Copy src/agent/loop.py — self-correcting loop
[ ] Copy src/agent/prompts.py — DFIR analyst prompt
[ ] Test: agent runs against test evidence

HOUR 7-8: Testing
[ ] Run against known-good data
[ ] Document first findings
[ ] Record first self-correction
[ ] Start accuracy report

HOUR 9-12: Submission Prep
[ ] Record demo video
[ ] Build architecture diagram
[ ] Write project description
[ ] Export execution logs
[ ] Upload to Devpost
```

---

## ⚠️ COMMON PITFALLS TO AVOID

| Pitfall | Why Deadly | How to Avoid |
|---------|------------|--------------|
| Only prompt-based guardrails | Judges create bypasses | Architectural enforcement always |
| No self-correction in demo | Violates explicit requirement | Film the recovery, not just success |
| Incomplete submission | Missing component = elimination | Use checklist, verify all 8 |
| Hallucinated findings | Destroys credibility | Accuracy report documents every miss |
| No audit trail | Criterion 5 score = 0 | Every tool call logged with trace |
| Shallow coverage of all types | Violates Criterion 3 | Go deep on disk + memory only |
| Over-engineered architecture | Wasted time on non-core | Focus on 10 P0 tools |
| Ignoring evidence integrity | Maximum penalty | Test spoliation, document results |

---

## FINAL SCORING ESTIMATE

Based on our analysis of the judges and criteria, here's how different approaches score:

| Approach | Auto Exec | IR Accuracy | Depth | Constraints | Audit | Usability | **TOTAL** |
|----------|:---------:|:-----------:|:----:|:-----------:|:-----:|:---------:|:---------:|
| **Our Hybrid (Plan A)** | 9/10 | 9/10 | 8/10 | 10/10 | 10/10 | 9/10 | **92/100** |
| Pure Custom MCP | 9/10 | 9/10 | 6/10 | 10/10 | 9/10 | 6/10 | 82/100 |
| Pure Direct Extension | 7/10 | 7/10 | 5/10 | 4/10 | 7/10 | 10/10 | 67/100 |
| Multi-Agent Only | 8/10 | 8/10 | 9/10 | 5/10 | 8/10 | 5/10 | 72/100 |
| Alternative IDE | 5/10 | 5/10 | 4/10 | 2/10 | 5/10 | 8/10 | 48/100 |

**Conclusion:** The Hybrid Approach (Custom MCP Server + Agent Extension) scores highest because it maxes out the three highest-weighted criteria: Constraints (10), Audit Trail (10), and Autonomous Execution (9).

---

*Recommendations v1.0 — Generated by God Syndicate Arsenal ORCHESTRATOR*
