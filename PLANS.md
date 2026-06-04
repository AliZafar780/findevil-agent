# FIND EVIL! — Strategic Attack Plans

> **Phase-by-phase execution plans for winning the Find Evil! Hackathon**
> Timeline: June 3 → June 15, 2026 (12 days)

---

## PLAN A: HYBRID APPROACH (RECOMMENDED — HIGHEST WIN PROBABILITY)

Combine Custom MCP Server (Approach 2) + Direct Agent Extension (Approach 1)
**Estimated score potential: 92/100**

### Phase 1: Foundation (Days 1-2)

```
DAY 1: Environment Setup
├── Install SIFT Workstation (Docker)
│   └── docker pull sansdfir/sift
│   └── docker run --rm -it -v /cases:/cases sansdfir/sift /bin/bash
├── Install Protocol SIFT
│   └── curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
├── Clone and explore
│   └── git clone https://github.com/teamdfir/protocol-sift
├── Download test evidence
│   └── NIST CFReDS datasets
│   └── SANS DFIR challenge images
└── Verify all 200+ tools accessible
    └── ./scripts/env_check.sh

DAY 2: Architecture Design
├── Map tool inventory → typed functions
├── Design MCP server schema
├── Define evidence integrity boundaries
├── Plan audit trail logging format
└── Create project skeleton
    └── pyproject.toml, configs, tests/
```

### Phase 2: Core MCP Server (Days 3-6)

```
DAY 3: Base MCP Server + P0 Tools
├── mcp_server/server.py — FastMCP app entrypoint
├── mcp_server/tools/__init__.py
├── mcp_server/tools/filesystem.py
│   ├── analyze_partition_table(image_path) -> List[Partition]
│   ├── list_directory(image_path, inode) -> List[FileEntry]
│   ├── extract_file(image_path, inode) -> bytes
│   └── get_inode_metadata(image_path, inode) -> InodeInfo
├── mcp_server/tools/timeline.py
│   ├── build_timeline(image_path, output_path) -> TimelineMeta
│   └── filter_timeline(storage_path, query) -> TimelineResults
├── mcp_server/security.py — Path validation, read-only enforcement
├── mcp_server/audit.py — Structured logging, trace capture
└── tests/test_p0_tools.py

DAY 4: P1 Tools — Deep Analysis
├── mcp_server/tools/memory.py
│   ├── analyze_memory(memory_path, plugin) -> MemoryResults
│   └── list_processes(memory_path) -> List[Process]
├── mcp_server/tools/carving.py
│   ├── carve_files(image_path, types) -> List[CarvedFile]
│   └── extract_features(image_path, scanners) -> FeatureResults
├── mcp_server/tools/registry.py
│   ├── query_registry(hive_path, key) -> RegistryResults
│   └── analyze_registry_hive(hive_path) -> HiveAnalysis
├── mcp_server/tools/network.py
│   ├── analyze_pcap(pcap_path, filters) -> PacketAnalysis
│   └── extract_streams(pcap_path) -> List[Stream]
└── tests/test_p1_tools.py

DAY 5: P2 Tools + Polish
├── mcp_server/tools/hashing.py
├── mcp_server/tools/patterns.py (yara)
├── mcp_server/tools/strings.py
├── mcp_server/middleware.py — Logging, rate limiting, error handling
└── tests/integration_test.py

DAY 6: Agent Loop + Self-Correction
├── agent/loop.py — ReAct pattern with:
│   ├── Tool selection intelligence
│   ├── Output evaluation + self-correction
│   ├── Context window management (chunking)
│   ├── Max-iteration safety caps
│   └── Graceful degradation
├── agent/prompts.py — DFIR analyst system prompt
├── agent/output_parsers.py — Structured result extraction
└── agent/logging.py — Full execution trace capture
```

### Phase 3: Testing & Accuracy (Days 7-8)

```
DAY 7: Accuracy Benchmarking
├── Test against known-good datasets
│   ├── NIST CFReDS: https://cfreds-archives.nist.gov/
│   ├── SANS DFIR challenge images
│   └── Custom test harness
├── Measure:
│   ├── True positive rate
│   ├── False positive rate
│   ├── False negative rate
│   ├── Hallucination rate
│   └── Average execution time
├── Document every failure mode
└── Implement fixes for top failures

DAY 8: Self-Correction Validation
├── Test failure recovery scenarios
│   ├── Tool timeout → retry with narrower scope
│   ├── Corrupt image → alternative approach
│   ├── Empty result → try different tool
│   └── Context overflow → summarize + continue
├── Record self-correction examples for demo
├── Test evidence integrity (spoliation)
└── Document guardrail bypass attempts
```

### Phase 4: Submission Package (Days 9-11)

```
DAY 9: Core Components
├── github.com/yourname/findevil-agent (public repo)
├── README.md — Try-It-Out Instructions
├── LICENSE (MIT)
├── pyproject.toml
└── Architecture Diagram
    ├── draw.io / excalidraw
    ├── Show: agent → MCP → SIFT tools → evidence
    ├── Mark: trust boundaries, guardrail types
    └── Export: PNG + SVG

DAY 10: Deliverables
├── Demo Video Script
│   ├── Intro (30s): Problem statement
│   ├── Setup (30s): Environment overview
│   ├── Live execution (3min): Agent running against evidence
│   ├── Self-correction (30s): Visible recovery
│   └── Results (30s): Findings summary
├── Record Demo Video (≤5 min)
├── Written Project Description
├── Dataset Documentation
├── Accuracy Report (CRITICAL)
│   ├── False positives documented
│   ├── Hallucinated claims flagged
│   ├── Evidence integrity approach
│   └── Guardrail test results
└── Agent Execution Logs (structured JSON)

DAY 11: Polish + Submit
├── Final review against all 8 components
├── Test try-it-out instructions on clean environment
├── Review accuracy report honesty
├── Upload to Devpost
└── Submit before June 15 @ 11:45 PM EDT
```

### Phase 5: Buffer (Day 12)

```
DAY 12: Buffer Day
├── Respond to judge questions
├── Fix any issues found during review
├── Optional: Add bonus features
└── Celebrate 🎉
```

---

## PLAN B: DIRECT AGENT EXTENSION (FAST TRACK — 7 DAYS)

For teams with less time or lower risk tolerance.
**Estimated score potential: 72/100**

```
DAYS 1-2: Environment + Research
├── Install SIFT + Protocol SIFT
├── Study existing agent loop code
├── Identify weakest points (hallucination, context overflow)
└── Plan improvements

DAYS 3-4: Agent Loop Improvements
├── Better system prompts for DFIR reasoning
├── Output validation + self-correction logic
├── Context window management (truncation + summarization)
├── Tool selection heuristics
└── Error recovery patterns

DAYS 5-6: Testing + Accuracy
├── Test against SIFT test images
├── Document accuracy metrics
├── Record self-correction examples
└── Build submission package

DAY 7: Submit
├── Complete all 8 components
└── Upload to Devpost
```

---

## PLAN C: MULTI-AGENT FRAMEWORK (DEEP — 12 DAYS)

For teams with strong AI/ML background wanting maximum depth.
**Estimated score potential: 85/100**

```
PHASE 1 (D1-3): Infrastructure
├── SIFT + Protocol SIFT setup
├── Agent framework selection (CrewAI or AutoGen recommended)
├── Design agent roles: Disk Analyst, Memory Analyst, Network Analyst, Synthesizer
└── MCP server for tool access

PHASE 2 (D4-7): Agent Development
├── Disk Analysis Agent: fls, icat, istat, mmls
├── Memory Analysis Agent: volatility, lime
├── Network Analysis Agent: tshark, tcpdump, yara
├── Timeline Agent: log2timeline, psort, mactime
├── Synthesis Agent: cross-references findings, builds narrative
└── Manager Agent: orchestrates, handles failures

PHASE 3 (D8-10): Testing + Submission
├── Inter-agent communication logging
├── Accuracy benchmarking
├── Self-correction demonstrations
├── Submission package (8 components)
└── Upload to Devpost
```

---

## RISK REGISTER

| Risk | Plan A | Plan B | Plan C | Mitigation |
|------|--------|--------|--------|------------|
| Not enough time | Medium | Low | High | Use Plan A with aggressive MVP scope |
| Tool integration fails | Medium | Low | High | Focus on 10 core tools, not all 200 |
| Context overflow crashes | Low | Medium | Medium | Implement chunking day 1 |
| Team coordination issues | Low | Low | Medium | Daily standups, shared task board |
| Submission missing component | Low | Low | Low | Checklist template from day 1 |
| Hallucinations not caught | Low | Medium | Medium | Cross-validation + accuracy report |

---

## RESOURCE ALLOCATION

```
Plan A Resource Budget (12 days, 1-5 person team):
├── 30% — MCP Server Development (24 person-hours)
├── 20% — Agent Loop + Self-Correction (16 person-hours)
├── 20% — Testing + Accuracy Benchmarking (16 person-hours)
├── 20% — Submission Package (16 person-hours)
└── 10% — Buffer / Overhead (8 person-hours)

Priority Order:
1. MCP server with 10 core tools (P0)
2. Agent loop with self-correction
3. Demo video — single self-correction sequence
4. Accuracy report — honest assessment
5. Everything else
```

---

## SUBMISSION CHECKLIST

```
[ ] 1. Code Repository — GitHub, public, MIT license
[ ] 2. Demo Video — ≤5 min, terminal screencast, audio narration
[ ] 3. Architecture Diagram — trust boundaries marked
[ ] 4. Project Description — What/How/Challenges/Learnings/Next
[ ] 5. Dataset Documentation — source, test data, findings
[ ] 6. Accuracy Report — FP, missed, hallucinations, integrity approach
[ ] 7. Try-It-Out Instructions — step-by-step reproduction
[ ] 8. Agent Execution Logs — structured JSON, full trace
```

---

*Plans v1.0 — Generated by God Syndicate Arsenal ORCHESTRATOR*
