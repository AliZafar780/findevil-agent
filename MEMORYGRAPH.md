# FIND EVIL! — MemoryGraph Knowledge Base

> **Smart Memory Graph**: Complete semantic map of the Find Evil! hackathon ecosystem.
> Generated: 2026-06-03 | Deadline: June 15, 2026

---

## 1. GRAPH OVERVIEW

```
                    ┌─────────────────────────────────────┐
                    │         FIND EVIL! HACKATHON         │
                    │    $22,000 · 3920 participants       │
                    │    Deadline: Jun 15, 2026 @ 11:45pm  │
                    └────────────────────┬────────────────┘
                                         │
            ┌────────────────────────────┼────────────────────────────┐
            ▼                            ▼                            ▼
    ┌───────────────┐          ┌───────────────────┐       ┌──────────────────┐
    │  SIFT         │◄────────►│  Protocol SIFT     │◄─────►│  Judging         │
    │  Workstation  │          │  (MCP Framework)   │       │  Criteria (6)    │
    │  (200+ tools) │          └───────────────────┘       └──────────────────┘
    └───────────────┘                      │                         │
            │                               │                         │
            ▼                               ▼                         ▼
    ┌───────────────────┐          ┌───────────────────┐       ┌──────────────────┐
    │ Tool Categories   │          │ Arch Approaches   │       │ Submission       │
    │ • Disk Forensics  │          │ (4 patterns)      │       │ Requirements     │
    │ • Memory Forensics│          │ • Direct Agent    │       │ (8 components)   │
    │ • Network Forensics│         │ • Custom MCP      │       └──────────────────┘
    │ • Log Analysis    │          │ • Multi-Agent     │
    │ • Registry        │          │ • Alt IDE         │
    │ • File Carving    │          └───────────────────┘
    │ • Timeline        │
    └───────────────────┘
```

---

## 2. KNOWLEDGE NODES

### 2.1 Hackathon Metadata

| Property | Value |
|----------|-------|
| **Name** | FIND EVIL! |
| **Platform** | Devpost |
| **Deadline** | June 15, 2026 @ 11:45 PM EDT |
| **Total Prize Pool** | $22,000 cash + SANS training |
| **Participants** | 3,920 (and growing) |
| **Team Size** | 1–5 members |
| **Track** | Cybersecurity + Machine Learning/AI |
| **Difficulty** | Beginner Friendly |
| **Status** | Active |

### 2.2 Prize Nodes

```
1st Place — SLAYED EVIL ($10,000)
├── $10,000 cash
├── SANS Summit pass + hotel (per member)
├── SANS OnDemand course (per member)
└── SANS Webcast/Livestream presentation

2nd Place — HUNTED EVIL ($7,500)
├── $7,500 cash
├── SANS Summit pass + hotel (per member)
├── SANS OnDemand course (per member)
└── SANS Webcast/Livestream presentation

3rd Place — FOUND EVIL ($4,500)
├── $4,500 cash
└── SANS OnDemand course (per member)
```

### 2.3 Platform Nodes

#### SIFT Workstation
- **Type:** Ubuntu-based forensic analysis platform
- **Tools:** 200+ open-source DFIR tools
- **Age:** 18 years of community development
- **Downloads:** 60K+ annual
- **Install:** `curl -L https://raw.githubusercontent.com/teamdfir/sift-saltstack/master/bootstrap.sh | sudo bash`
- **Docker:** `docker pull sansdfir/sift`
- **Key Categories:**
  - Disk Forensics (#disk)
  - Memory Forensics (#memory)
  - Network Forensics (#network)
  - Log Analysis (#logs)
  - Registry Analysis (#registry)
  - File Carving (#carving)
  - Timeline Analysis (#timeline)
  - Hashing & Integrity (#hash)
  - Pattern Matching (#yara)

#### Protocol SIFT
- **Type:** MCP Server + Agent Loop
- **Repo:** `github.com/teamdfir/protocol-sift`
- **Language:** Python
- **Install:** `curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash`
- **Architecture:**
  - MCP Server (`mcp_server/`) — wraps 25-30 SIFT tools
  - Agent Loop (`agent/`) — ReAct pattern for multi-step analysis
  - Config (`config/`) — TOML-based tool definitions
- **Key Tools Exposed:**
  - `sift_fls`, `sift_icat`, `sift_ifind`, `sift_ils`, `sift_istat`, `sift_fsstat`
  - `sift_mactime`, `sift_sigfind`, `sift_sorter`
  - `sift_foremost`, `sift_scalpel`, `sift_bulk_extractor`
  - `sift_reglookup`, `sift_log2timeline`, `sift_psort`
  - `sift_file`, `sift_hash`, `sift_strings`

### 2.4 Architectural Approach Nodes

#### Approach 1: Direct Agent Extension
- **Difficulty:** ★★ Easy
- **Speed:** Fastest path
- **Risk:** Low
- **Score Potential:** Medium
- **Strategy:** Extend Protocol SIFT's existing Claude Code / OpenClaw agent loop
- **Key Work:** Better prompts, tool sequencing, self-correction, accuracy validation
- **Best for:** Quick wins, iterative improvement

#### Approach 2: Custom MCP Server
- **Difficulty:** ★★★★★ Hard
- **Speed:** Highest effort
- **Risk:** High (if not done well)
- **Score Potential:** MAXIMUM
- **Strategy:** Build purpose-built MCP server exposing typed functions instead of shell commands
- **Key Work:** `get_amcache()`, `extract_mft_timeline()`, `analyze_prefetch()` as typed functions
- **Best for:** Winning — judges explicitly call this "the most sound architecture"

#### Approach 3: Multi-Agent Frameworks
- **Difficulty:** ★★★★ Advanced
- **Speed:** Medium
- **Risk:** Medium (agent loops can infinite-spiral)
- **Score Potential:** High
- **Strategy:** Decompose analysis into specialized agents (memory, disk, network, synthesis)
- **Key Work:** AutoGen/CrewAI/LangGraph orchestration, agent communication logging
- **Best for:** Complex cases, showing depth

#### Approach 4: Alternative Agentic IDEs
- **Difficulty:** ★★★ Medium
- **Speed:** Medium
- **Risk:** Medium (prompt-based guardrails only)
- **Score Potential:** Lower
- **Strategy:** Use Cursor/Cline/Aider with custom rules
- **Key Work:** Rule files, prompt adherence documentation
- **Best for:** Teams familiar with these tools

### 2.5 Judging Criteria Nodes

| # | Criterion | Weight | What Judges Look For |
|---|-----------|--------|---------------------|
| 1 | **Autonomous Execution Quality** | Tiebreaker | Self-correction, reasoning chains, failure recovery |
| 2 | **IR Accuracy** | High | Correct findings, hallucinations flagged, confirmed vs inferred |
| 3 | **Breadth & Depth** | High | Depth on fewer types beats shallow coverage of many |
| 4 | **Constraint Implementation** | Critical | Architectural vs prompt-based guardrails — TESTED |
| 5 | **Audit Trail Quality** | High | Traceability: finding → tool execution → raw output |
| 6 | **Usability & Documentation** | Medium | Can another practitioner deploy and build on this? |

### 2.6 Submission Component Nodes

Each submission requires ALL 8 components:

| # | Component | Format | Key Content |
|---|-----------|--------|-------------|
| 1 | Code Repository | GitHub | Public, MIT/Apache 2.0 |
| 2 | Demo Video | ≤5 min | Live terminal + audio, ≥1 self-correction |
| 3 | Architecture Diagram | Visual | Trust boundaries, guardrail types |
| 4 | Project Description | Markdown | What/How/Challenges/Learnings/Next |
| 5 | Dataset Documentation | Markdown | Source, what tested, findings |
| 6 | Accuracy Report | Markdown | FP, missed, hallucinations + evidence integrity |
| 7 | Try-It-Out | README | Step-by-step reproduction |
| 8 | Agent Execution Logs | Structured JSON | Full trace, timestamps, token usage |

### 2.7 Judge Nodes (27 experts)

| Judge | Title | Organization | Domain |
|-------|-------|-------------|--------|
| Rob T. Lee | CAIO | SANS Institute | DFIR (Chair) |
| Ahmed AbuGharbia | Founder | cyberdojo.ai | AI Security |
| Brad Edwards | Domain Consultant | Palo Alto Networks | SecOps |
| Brett Cumming | CISO | Skechers | Security Leadership |
| Steve Cobb | CISO | SecurityScorecard | Cybersecurity |
| Saurabh Naik | Head of Red Team | Lockheed Martin | Red Team |
| Jason Garman | Principal Security Specialist | AWS | Cloud Security |
| Amanda Rankhorn | FBI Special Agent (Ret.) | — | Forensics |
| John Wilson | CISO | HaystackID | Forensics |
| Ovie Carroll | Director | DOJ Cybercrime Lab | Cybercrime |
| Yotam Perkal | Director Security Research | Pluto Security | Research |
| + 15 more | Various | Various | DFIR/AI/Security |

### 2.8 Tool Ecosystem Nodes

```
SIFT Tools (200+)              MCP Ecosystem          Agent Frameworks
├── sleuthkit (fls, icat)     ├── FastMCP             ├── Claude Code
├── volatility (mem analysis)  ├── Python MCP SDK     ├── OpenClaw
├── plaso (log2timeline)       ├── Node.js MCP SDK    ├── AutoGen
├── bulk_extractor             ├── STDIO Transport    ├── CrewAI
├── foremost / scalpel         ├── SSE Transport      ├── LangGraph
├── regripper / regipy         └── MCP Inspector      └── Cursor/Cline
├── yara
├── tshark / tcpdump
├── ewftools
└── hashdeep / md5deep
```

---

## 3. RELATIONSHIP EDGES

### 3.1 Tool → Category Mappings

| Tool | Category | MCP Function Name |
|------|----------|-------------------|
| `fls` | File System | `sift_fls()` |
| `icat` | File System | `sift_icat()` |
| `istat` | File System | `sift_istat()` |
| `fsstat` | File System | `sift_fsstat()` |
| `mmls` | Partitions | `(proposed) sift_mmls()` |
| `vol.py` | Memory | `(proposed) sift_volatility()` |
| `log2timeline` | Timeline | `sift_log2timeline()` |
| `psort` | Timeline | `sift_psort()` |
| `bulk_extractor` | Feature Extraction | `sift_bulk_extractor()` |
| `foremost` | Carving | `sift_foremost()` |
| `scalpel` | Carving | `sift_scalpel()` |
| `reglookup` | Registry | `sift_reglookup()` |
| `yara` | Pattern Matching | `(proposed) sift_yara()` |
| `tshark` | Network | `(proposed) sift_tshark()` |
| `hashdeep` | Hashing | `sift_hash()` |
| `file` | File ID | `sift_file()` |
| `strings` | Extraction | `sift_strings()` |

### 3.2 Architectural Approach → Judging Criteria

| Approach | Auto Exec Quality | IR Accuracy | Breadth/Depth | Constraints | Audit Trail | Usability |
|----------|:---:|:---:|:---:|:---:|:---:|:---:|
| Direct Agent Extension | ★★★ | ★★★ | ★★ | ★★ | ★★★ | ★★★★★ |
| Custom MCP Server | ★★★★★ | ★★★★★ | ★★★★ | ★★★★★ | ★★★★★ | ★★★ |
| Multi-Agent Frameworks | ★★★★ | ★★★★ | ★★★★★ | ★★★ | ★★★★ | ★★ |
| Alternative IDE | ★★ | ★★ | ★★ | ★ | ★★ | ★★★★ |

### 3.3 Risk → Mitigation Matrix

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Context window overflow | High | High | Implement chunking + summarization mid-loop |
| Tool timeout on large images | High | Medium | Configurable timeout + scope reduction |
| Agent infinite loop | High | Medium | Max-iteration caps, graceful degradation |
| Evidence spoliation | Critical | Low | Read-only mounts, typed MCP functions |
| Hallucinated findings | High | High | Self-correction, cross-validation, accuracy report |
| Submission component incomplete | Critical | Medium | Checklist automation, template generation |

### 3.4 Dependency Graph for Winning

```
WINNING SUBMISSION
├── Strong Autonomous Execution (Criterion 1)
│   ├── Self-correction loop (REQUIRED)
│   ├── Tool sequencing intelligence
│   └── Failure recovery patterns
├── IR Accuracy (Criterion 2)
│   ├── Tested against known-good datasets
│   ├── Hallucination detection mechanism
│   └── False positive/negative documentation
├── Constraint Implementation (Criterion 4 — KEY DIFFERENTIATOR)
│   ├── ARCHITECTURAL guardrails > prompt-based
│   ├── Tested for bypass
│   └── Documentation of failure modes
├── Audit Trail (Criterion 5)
│   ├── Every finding traceable to tool execution
│   ├── Timestamps, token usage, raw output capture
│   └── Structured JSON logs
└── Complete Submission Package (All 8 components)
```

---

## 4. CAPABILITY INVENTORY (Our Arsenal)

### 4.1 Ready-to-Use MCP Servers

| MCP Server | Can We Use It? | For What? |
|------------|:------------:|-----------|
| bash-mcp | ✅ Yes | Shell command execution inside SIFT |
| python-mcp | ✅ Yes | Python scripting for custom analysis |
| docker-mcp | ✅ Yes | Running SIFT Docker container |
| http-mcp / curl-mcp | ✅ Yes | API integrations, evidence downloads |
| crypto-mcp | ✅ Yes | Hash verification, encryption analysis |
| network-mcp | ✅ Yes | Network capture analysis |

### 4.2 Skills We Can Apply

| Skill | Relevance to Hackathon |
|-------|----------------------|
| **mcp-builder** | HIGH — Build custom MCP server for SIFT tools |
| **claude-api** | HIGH — Claude Code integration, agent loops |
| **multi-agent-orchestrat** | HIGH — Multi-agent framework patterns |
| **prompt-engineering** | HIGH — System prompt design for DFIR agents |
| **secure-coding** | MEDIUM — Evidence integrity, security boundaries |
| **python-project** | MEDIUM — Project structure, testing, packaging |
| **batch-changes** | LOW — Large-scale refactoring (if building many tools) |

### 4.3 Available Agent Types

| Agent | Can Help With |
|-------|--------------|
| `web-app-pentester` | Understanding attack patterns for detection |
| `network-pentester` | Network forensics, pcap analysis |
| `exploit-dev` | Understanding exploit artifacts |
| `binary-reverser` | Malware/binary analysis |
| `osint-analyst` | Threat intelligence context |
| `docs-writer` | Documentation, reports, README |

---

## 5. STRATEGIC INSIGHTS

### 5.1 The Winning Formula

From analyzing the judges, criteria, and competition:

```
WEIGHTED SCORING MODEL
┌──────────────────────────────────────────────┐
│ 1. Custom MCP Server (40% of score)          │
│    → Architecture + Constraints + Audit      │
│                                              │
│ 2. Self-Correction Loop (25% of score)       │
│    → Autonomous execution + Accuracy         │
│                                              │
│ 3. Complete Submission Package (20% of score)│
│    → All 8 components, quality docs          │
│                                              │
│ 4. Depth on Core Artifacts (15% of score)    │
│    → Master disk + memory, skip the rest     │
└──────────────────────────────────────────────┘
```

### 5.2 Key Quote from Judges

> *"This is the most sound architecture in the evaluation. It's also the most work."* — on Custom MCP Server

> *"If your submission uses an alternative IDE, your accuracy report must document what happens when the model ignores read-only rules."* — on guardrails

> *"Did you test for spoliation? If you found failure modes, document them. That's signal, not weakness."* — on evidence integrity

### 5.3 Time Available

- **Today:** June 3, 2026
- **Deadline:** June 15, 2026 @ 11:45 PM EDT
- **Days remaining:** 12 days
- **Optimal strategy:** Hybrid Approach 1 + Approach 2
  - Week 1: Build Custom MCP Server for 10-15 key tools
  - Week 2: Build self-correction loop + submission package

---

## 6. CRITICAL SUCCESS FACTORS

| Factor | Priority | Action |
|--------|----------|--------|
| Evidence integrity | 🔴 CRITICAL | Read-only mounts, typed functions, test for bypass |
| Self-correction demo | 🔴 CRITICAL | At least 1 visible in video |
| Complete 8/8 submission | 🔴 CRITICAL | Template every component |
| Architectural guardrails | 🟡 HIGH | Prefer over prompt-based |
| Audit trail logging | 🟡 HIGH | Structured JSON, full trace |
| Hallucination handling | 🟡 HIGH | Detection + flagging mechanism |
| Known-good dataset | 🟢 MEDIUM | SIFT test images, NIST datasets |
| Multi-agent parallelism | 🟢 MEDIUM | If time permits |

---

## 7. DATA FLOW MAP

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────────┐
│  RAW EVIDENCE│────►│  Custom MCP      │────►│  Agent Loop          │
│  (disk img,  │     │  Server           │     │  (ReAct Pattern)     │
│   memory,    │     │                   │     │                      │
│   pcap)      │     │  ┌─────────────┐  │     │  ┌────────────────┐  │
└──────────────┘     │  │ Typed       │  │     │  │ Tool Selection │  │
                     │  │ Functions   │  │     │  │ → Execute      │  │
                     │  │ • get_mft() │  │     │  │ → Evaluate     │  │
                     │  │ • get_mem() │  │     │  │ → Self-Correct │  │
                     │  │ • get_logs()│  │     │  │ → Log          │  │
                     │  └─────────────┘  │     │  └────────────────┘  │
                     └──────────────────┘     └──────────┬───────────┘
                                                          │
                                                          ▼
                                               ┌──────────────────────┐
                                               │  OUTPUT PIPELINE     │
                                               │  ├── Findings JSON   │
                                               │  ├── Execution Logs  │
                                               │  ├── Accuracy Report │
                                               │  └── Demo Artifacts  │
                                               └──────────────────────┘
```

---

## 8. TOOL PRIORITY MATRIX (for MCP Wrapping)

| Priority | Tool | Function | Use Case | Complexity |
|----------|------|----------|----------|------------|
| P0 | `fls` | List files | File system analysis | Low |
| P0 | `icat` | Extract files | File recovery | Low |
| P0 | `istat` | Inode metadata | Deep file analysis | Low |
| P0 | `mmls` | Partition list | Evidence triage | Low |
| P0 | `log2timeline` | Timeline build | Core timeline | Medium |
| P0 | `bulk_extractor` | Feature extraction | Quick wins | Medium |
| P1 | `vol.py` | Memory analysis | Deep analysis | High |
| P1 | `psort` | Timeline filter | Timeline refinement | Medium |
| P1 | `foremost` | File carving | Data recovery | Low |
| P1 | `reglookup` | Registry analysis | Windows forensics | Low |
| P1 | `tshark` | PCAP analysis | Network forensics | Medium |
| P1 | `yara` | Pattern matching | Malware detection | Medium |
| P2 | `hashdeep` | Integrity | Verification | Low |
| P2 | `srch_strings` | String search | Artifact discovery | Low |
| P2 | `sorter` | File categorization | Organization | Low |

---

*MemoryGraph v1.0 — Generated by God Syndicate Arsenal ORCHESTRATOR*
