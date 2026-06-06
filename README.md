<div align="center">
  <pre>
                           ;
     Et                          ED.
     E#t          L.             E#Wi                       ,;
     E##t     t   EW:        ,ft E###G.                   f#i            t              i
     E#W#t    Ej  E##;       t#E E#fD#W;                .E#t             Ej            LE
     E#tfL.   E#, E###t      t#E E#t t##L              i#W,   t      .DD.E#,          L#E
     E#t      E#t E#fE#f     t#E E#t  .E#K,           L#D.    EK:   ,WK. E#t         G#W.
  ,ffW#Dffj.  E#t E#t D#G    t#E E#t    j##f        :K#Wfff;  E#t  i#D   E#t        D#K.
   ;LW#ELLLf. E#t E#t  f#E.  t#E E#t    :E#K:       i##WLLLLt E#t j#f    E#t       E#K.
     E#t      E#t E#t   t#K: t#E E#t   t##L          .E#L     E#tL#i     E#t     .E#E.
     E#t      E#t E#t    ;#W,t#E E#t .D#W;             f#E:   E#WW,      E#t    .K#E
     E#t      E#t E#t     :K#D#E E#tiW#G.               ,WW;  E#K:       E#t   .K#D
     E#t      E#t E#t      .E##E E#K##i                  .D#; ED.        E#t  .W#G
     E#t      E#t ..         G#E E##D.                     tt t          E#t :W##########Wt
     ;#t      ,;.             fE E#t                                     ,;. :,,,,,,,,,,,,,.
      :;                       , L:
  </pre>
  <h1>FindEvil Agent</h1>
  <p>
    <strong>Autonomous DFIR Analysis Agent</strong><br>
    AI-Powered Digital Forensics &amp; Incident Response
  </p>
  <p>
    <a href="https://github.com/AliZafar780/findevil-agent"><img src="https://img.shields.io/badge/version-2.1.4-blue?style=flat-square&logo=github" alt="Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
    <a href="https://github.com/AliZafar780/findevil-agent/actions"><img src="https://img.shields.io/badge/build-CI%20%7C%20Docker%20%7C%20Lint%20%7C%20Type%20Check-blue?style=flat-square" alt="CI"></a>
    <img src="https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12%20|%203.13-blue?style=flat-square&logo=python" alt="Python">
    <img src="https://img.shields.io/badge/tests-107%20passing-brightgreen?style=flat-square" alt="Tests">
    <img src="https://img.shields.io/badge/tools-22%20MCP-informational?style=flat-square" alt="Tools">
    <img src="https://img.shields.io/badge/AI-Groq%20%7C%20Deterministic%20Mode-orange?style=flat-square" alt="AI">
  </p>
  <p>
    <code># dfir</code> <code># incident-response</code> <code># forensics</code> <code># mcp</code> <code># memory-forensics</code>
  </p>
</div>

---

## 🔥 Overview

**FindEvil** is an autonomous digital forensics and incident response agent that orchestrates **22 MCP forensic tools** across memory, filesystem, registry, network, and carving analysis. It supports **Groq AI** for intelligent tool selection and report generation, and runs fully in **deterministic mode without any API key**.

> _"Find Evil, find answers, find closure."_

### Key Highlights

| Capability | Status |
|---|---|
| 🔌 **22 MCP Forensic Tools** | Disk, memory, registry, network, carving, hashing, YARA |
| 🤖 **AI Integration** | Groq Llama 3.3 70B (optional — deterministic mode always works) |
| ✅ **Zero API Key Required** | All features operational without Groq, Shodan, or any external key |
| 🛡️ **Security Hardened** | Path traversal blocked, null bytes rejected, async lock concurrency |
| ⚡ **Performance Tuned** | Lazy imports, cached tool resolution, buffered audit writes |
| 📊 **Confidence Scoring** | Per-tool data quality: CONFIRMED / INFERRED / UNVERIFIED |
| 💰 **Token Budget Caps** | Max 100K tokens/session (~$0.07) with real-time tracking |
| 🧪 **107 Passing Tests** | Unit (41) + Integration (66) across CLI, tools, parser, server, edge cases |
| 🐳 **Docker** | Multi-stage build: python:3.11-slim → ubuntu:24.04 with sleuthkit, yara, tshark, foremost, bulk-extractor |
| 🔄 **CI/CD** | GitHub Actions: lint, type-check, test (4 Python versions), build, Docker, security audit |
| 📈 **Gap Analysis** | Comprehensive 33-gap audit closed — [GAP_ANALYSIS.md](GAP_ANALYSIS.md) |

---

## 🎬 Quick Demo

```bash
# 1. Install
git clone https://github.com/AliZafar780/findevil-agent.git && cd findevil-agent
pip install -e .

# 2. Check environment (2 seconds)
findevil check

# 3. Generate a test image with real IOCs
findevil create-test-image test.dd

# 4. Run full autonomous investigation
findevil investigate test.dd --output ./results

# 5. Try a single tool
findevil tool fs_list_files --image test.dd
```

**Without any API key** — the AI features automatically disable and the system runs in deterministic mode. For AI-powered analysis, set `GROQ_API_KEY` and re-run.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         FindEvil Agent                             │
├────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────┐ │
│  │  CLI (rich)   │   │ MCP Server   │   │ Groq AI / Deterministic│ │
│  │  findevil     │──▶│ 22 Tools API │──▶│ Tool Selector + Report │ │
│  └──────────────┘   └──────┬───────┘   └───────────┬────────────┘ │
│                            │                        │              │
│  ┌─────────────────────────┴──────────────────────┐ │              │
│  │            DFIR Workflow Engine                 │ │              │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ │ │              │
│  │  │Triage│→│  FS   │→│Carve │→│Memory│→│Registry│ │              │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ │ │              │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐          │ │              │
│  │  │Network││Hashing││ YARA ││Timeline│          │ │              │
│  │  └──────┘ └──────┘ └──────┘ └──────┘          │ │              │
│  └────────────────────────────────────────────────┘ │              │
│                            │                        │              │
│  ┌─────────────────────────┴──────────────────────┐ │              │
│  │         Tool Resolver + Config/Tools.TOML       │ │              │
│  │  fls │ icat │ mmls │ foremost │ yara │ tshark   │              │
│  │  bulk_extractor │ hashdeep │ volatility3 │ regipy │              │
│  └────────────────────────────────────────────────┘              │
└────────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Evidence Input** → Disk images (raw, E01), memory dumps (raw, ELF), PCAPs, registry hives
2. **Triage** → Verify integrity via hashing (SHA256/SHA1/MD5), inspect filesystem metadata
3. **Filesystem Analysis** → List files, extract metadata, recover deleted content via TSK
4. **Artifact Extraction** → Carve deleted files, scan with YARA rules
5. **Memory Analysis** → List processes, scan network connections, dump command lines
6. **Registry Analysis** → Parse hive files, extract keys and values
7. **Network Analysis** → Analyze PCAPs, extract protocols, reconstruct conversations
8. **Timeline** → Export MAC timelines for temporal correlation
9. **AI/Deterministic Report** → Groq LLM or built-in narrative report generator

---

## ✨ Features

### Tool Categories

| Category | Tools | Backend |
|---|---|---|
| 🔍 **Filesystem** | `fs_partition_scan`, `fs_list_files`, `fs_file_metadata`, `fs_extract_file`, `fs_filesystem_info` | TSK (fls, icat, mmls, fsstat, istat) |
| 🧩 **Carving** | `carve_files` | foremost |
| 📋 **Hashing** | `verify_hash` | hashdeep / openssl |
| 🧬 **YARA** | `scan_yara` | yara (built-in rules for C2 domains, crypto miners, PowerShell abuse, webshells) |
| 🧠 **Memory** | `mem_list_processes`, `mem_analyze`, `mem_scan_network`, `mem_dump_cmdline` | Volatility 3 + string-based IOC fallback |
| 🪟 **Registry** | `reg_analyze_hive`, `reg_list_keys`, `reg_get_value` | regipy |
| 📡 **Network** | `pcap_analyze`, `pcap_list_protocols`, `pcap_extract_streams` | tshark |
| ℹ️ **Info** | `list_evidence`, `get_case_info`, `export_timeline` | TSK + built-in |
| ⚙️ **Config** | `get_tool_config` | config/tools.toml |

### MCP Server

FindEvil implements the **Model Context Protocol** (MCP), making all 22 tools available to any MCP-compatible LLM client (Claude Code, custom agents, etc.).

```json
{
  "mcpServers": {
    "findevil": {
      "command": "findevil",
      "args": ["serve"]
    }
  }
}
```

### Graceful Degradation

All features work **without any API key**:

| Feature | With API Key | Without API Key |
|---|---|---|
| Tool execution | ✅ | ✅ |
| Tool selection | ✅ (AI-optimized) | ✅ (deterministic fallback chains) |
| Report generation | ✅ (Groq narrative) | ✅ (built-in narrative generator) |
| Token tracking | ✅ | ✅ (capped at $0) |
| Audit trail | ✅ | ✅ |

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **System Tools** (recommended for full functionality):
  ```bash
  sudo apt install sleuthkit foremost yara tshark   # Linux
  brew install sleuthkit foremost yara tshark        # macOS
  ```
- **Groq API Key** (optional): [Get one free](https://console.groq.com)

### Install

```bash
git clone https://github.com/AliZafar780/findevil-agent.git
cd findevil-agent
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

### Verify

```bash
findevil check
```

### Run an Investigation

```bash
findevil investigate ./evidence.dd --output ./results
```

Without AI (deterministic mode — no API key needed):

```bash
findevil investigate ./evidence.dd --no-ai
```

Run a single phase:

```bash
findevil investigate ./evidence.dd --phase memory
```

### Generate a Test Image

```bash
findevil create-test-image test.dd --size 50
findevil investigate test.dd --no-ai
```

### Start MCP Server

```bash
findevil serve
```

### List & Call Tools

```bash
findevil tools
findevil tool fs_list_files --image evidence.dd
findevil tool scan_yara --image evidence.dd --rules "rule Bad { strings: \$a = \"evil\" condition: \$a }"
```

---

## 🧪 Tests

```bash
pytest tests/ -v                          # All tests
pytest tests/test_cli.py -v               # CLI tests (4)
pytest tests/test_forensic_tools.py -v    # Tool model & resolver tests (15)
pytest tests/test_groq_client.py -v       # Parser, selector, client tests (22)
pytest tests/test_server.py -v            # MCP server integration tests (11)
```

**107 tests passing** across 6 test suites:

| Suite | Type | Count | Coverage |
|---|---|---|---|
| CLI | Unit | 4 | Logo rendering, version, help, imports |
| Forensic Tools | Unit | 15 | Models (hash, pattern, filesystem, registry, network, timeline, memory), tool resolver |
| Groq Client | Unit | 22 | Client init, output parser (JSON extraction, tool decisions, reports), tool selector (suggestions, fallback chains) |
| Workflow | Integration | 2 | Agent loop phases, tool chaining |
| Edge Cases | Integration | 53 | Path traversal, missing evidence, carving security, YARA, large files, audit trail, concurrent access, error quality, wrong-tool rejection |
| Server | Integration | 11 | Tool execution, hash verification, evidence listing, path validation, null byte, missing params |

### CI Pipeline

GitHub Actions runs across **4 Python versions** (3.10, 3.11, 3.12, 3.13):

```
lint (ruff) → type-check (mypy) → test (pytest × 4 versions)
  → build (wheel) → Docker (multi-stage) → audit (pip-audit)
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | — | Groq API key (optional — all features work without it) |
| `EVIDENCE_ROOT` | `/evidence` | Default evidence directory |
| `RESULTS_ROOT` | `/results` | Default results directory |

### CLI Options

```bash
findevil investigate <evidence> [options]

Options:
  --output PATH      Output directory
  --task TEXT        Natural language task description
  --groq-model TEXT  Groq model (default: llama-3.3-70b-versatile)
  --no-ai            Skip AI — use deterministic report generator
  --phase PHASE      Run specific phase only
  --json             Output as JSON
  --debug            Enable debug logging
  --no-logo          Skip ASCII logo
```

### Tool Configuration (config/tools.toml)

Tool paths and arguments are defined in `config/tools.toml` and loaded at startup:

```toml
[tools.fls]
path = "fls"
args = ["-r", "-p", "{image_path}"]
description = "List file names in a disk image"
```

Query at runtime via the `get_tool_config` MCP tool.

---

## 🐳 Docker

```bash
docker build -t findevil-agent .
docker run --rm -v /evidence:/evidence findevil-agent investigate /evidence/case.dd
```

Multi-stage Dockerfile: `python:3.11-slim` builder → `ubuntu:24.04` runtime with sleuthkit, foremost, yara, tshark, bulk-extractor pre-installed.

---

## 📦 Project Structure

```
findevil-agent/
├── src/
│   ├── cli.py                   # Rich CLI entry point
│   ├── server.py                # MCP server (22 tools, async subprocess, audit, benchmarks)
│   ├── models.py                # Pydantic data models
│   ├── __main__.py              # Package entry point
│   ├── agent/
│   │   ├── loop.py              # DFIR workflow + evidence pre-validation
│   │   ├── groq_client.py       # Groq LLM + deterministic fallback
│   │   ├── output_parser.py     # Balanced-brace JSON extraction
│   │   ├── tool_selector.py     # 58-entry registry with fallback chains
│   └── tools/
│       ├── filesystem.py        # TSK wrappers (fls, icat, mmls, fsstat, istat)
│       ├── carving.py           # Foremost carving
│       ├── memory.py            # Volatility 3 + IOC scanning
│       ├── registry.py          # Regipy hive parsing
│       ├── network.py           # TShark PCAP analysis
│       ├── hashing.py           # hashdeep / openssl
│       ├── patterns.py          # YARA rules (C2, crypto, webshells, PS abuse)
│       ├── timeline.py          # MAC timeline export
│       ├── tool_resolver.py     # Cross-platform shutil.which() resolution
│       └── __init__.py
├── config/
│   ├── tools.toml               # Tool path & argument definitions
│   └── server.toml              # Server configuration
├── tests/
│   ├── test_cli.py              # CLI unit tests (4)
│   ├── test_forensic_tools.py   # Tool model tests (15)
│   ├── test_groq_client.py      # Parser/selector/client tests (22)
│   ├── test_server.py           # MCP server integration tests (11)
│   ├── test_edge_cases.py       # Edge case integration tests (53)
│   └── test_workflow.py         # Workflow tests
├── .github/workflows/ci.yml     # GitHub Actions CI/CD
├── Dockerfile                   # Multi-stage Docker build
├── pyproject.toml               # PEP 621 project config
└── GAP_ANALYSIS.md              # 33-gap audit and closure report
```

---

## 🔬 Gap Analysis

All 33 identified gaps have been closed across 13 phases:

| Phase | Area | Key Fixes |
|---|---|---|
| 1 | Critical Logic | Agent exit criteria, phantom tool calls, FALLBACKS typo, real IOCs |
| 2 | Security | Async tool execution, registry path oracle, memory detection, carve validation |
| 3 | Performance | Lazy imports, cached resolution, buffered audit |
| 4 | Testing | 41 new pytest tests, benchmark scoring |
| 5 | Polish | Token tracking, multi-stage Docker, balanced-brace JSON |
| 6 | Graceful Degradation | No API key required — all features work |
| 7 | CI/CD | GitHub Actions (5 jobs, 4 Python versions) |
| 8 | Confidence Scoring | Per-tool CONFIRMED/INFERRED/UNVERIFIED |
| 9 | Evidence Validation | Pre-check at loop start |
| 10 | Edge Cases | 50+ parametrized pytest tests |
| 11 | Logo | Professional DFIR-themed ASCII art |
| 12 | Config | config/tools.toml integrated |
| 13 | Types | All 22 handlers annotated |

See [GAP_ANALYSIS.md](GAP_ANALYSIS.md) for the full report.

---

## ❓ FAQ

### What image formats are supported?
Raw/dd images (`.dd`, `.raw`, `.img`, `.bin`), split raw images, E01/EWF (Expert Witness), and AFF4. Memory dumps: raw (`.raw`, `.mem`, `.bin`) and ELF (LiME output). PCAP/PCAPNG for network captures.

### How large can evidence files be?
Tested up to 50 GB raw images. The system uses streaming reads for carving and scans only the first 100 MB of large memory dumps for IOC strings. Hash computations scale linearly with file size (300s timeout).

### Can I analyze multiple evidence files at once?
Use `findevil investigate` with a directory: `findevil investigate /evidence/case_dir/` — the system runs triage on each file and processes them sequentially, merging results into one timeline and report.

### Why does `pip install -e .` not install Volatility/Regipy?
Those are in the optional `core` group. Install them explicitly:
```bash
pip install -e ".[core]"       # Core forensic tools
pip install -e ".[dev,core]"   # Everything for development
```

### How are Volatility plugins selected?
The system tries `linux.pslist.PsList`, `linux.malfind.Malfind`, `linux.netstat.Netstat`, `linux.bash.Bash` depending on the tool called. If none work, it falls back to string-based IOC scanning. macOS and Windows plugins are not yet supported — contributions welcome.

### What happens when a forensic tool isn't installed?
Every tool has a graceful fallback: missing YARA → built-in signature scanning, missing Volatility → string IOC scanning, missing TSK → reduced file listing, missing regipy → reglookup CLI (if available). The system never crashes from a missing tool.

### Does the AI mode require internet access?
Yes — the Groq API needs internet. Deterministic mode works fully offline with no API key. Run with `--no-ai` or omit `GROQ_API_KEY` entirely.

---

## 🐛 Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `Tool not found` | Forensic tool not installed | `sudo apt install sleuthkit foremost yara tshark` (Linux) or `brew install sleuthkit foremost yara tshark` (macOS) |
| `No partition table found` | Image is a raw filesystem (no MBR/GPT) | Normal — use `fs_filesystem_info` instead, or pass `--offset 0` |
| `Not a Registry hive file` | Wrong tool for the evidence | Memory/disk images can't be parsed as registry — use `fs_list_files` first to identify the evidence type |
| `Not a packet capture file` | Wrong tool for the evidence | Same as above — verify the evidence type with `fs_filesystem_info` |
| `AI returned no tools` | Parser couldn't extract JSON from LLM response | Falls back to deterministic mode automatically — no action needed |
| `Image contains no files` | Wrong offset or corrupted image | Try different partition offsets: `fs_partition_scan` first, then use the detected offset |
| `HAS_EVIDENCE=False` / tests skipped | No test image at `/evidence/cases/test.raw` | Run `findevil create-test-image /evidence/cases/test.raw` to generate one |
| `ModuleNotFoundError` | Package not installed | Run `pip install -e .` from the project root |

### Still stuck?

```bash
# Check your environment
findevil check

# Run with debug logging
findevil investigate ./evidence.dd --debug

# Or start a discussion on GitHub
```

---

## 🧩 Extending: Adding a New Forensic Tool

Each tool follows a 3-step pattern:

### Step 1: Write the tool logic (`src/tools/`)

```python
# src/tools/strings.py
import subprocess
from pydantic import BaseModel

class StringsResult(BaseModel):
    success: bool
    strings: list[str] = []
    error: str = ""

def extract_strings(image_path: str, min_len: int = 6) -> StringsResult:
    """Extract readable strings from a binary image."""
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_len), image_path],
            capture_output=True, text=True, timeout=60,
        )
        lines = [s for s in result.stdout.split("\n") if s.strip()]
        return StringsResult(success=True, strings=lines[:200])
    except Exception as e:
        return StringsResult(success=False, error=str(e))
```

### Step 2: Register in the MCP server (`src/server.py`)

```python
# 1. Import your module
from src.tools.strings import extract_strings, StringsResult

# 2. Add a Tool definition to `_register_tools()`
Tool(
    name="extract_strings",
    description="Extract ASCII/Unicode strings from a binary file",
    inputSchema={
        "type": "object",
        "properties": {
            "image_path": {"type": "string", "description": "Path to binary file"},
            "min_length": {"type": "integer", "description": "Minimum string length", "default": 6},
        },
        "required": ["image_path"],
    },
),

# 3. Add a handler function
async def _handle_extract_strings(args: dict) -> list[TextContent]:
    image_path = args["image_path"]
    min_len = args.get("min_length", 6)
    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    result = extract_strings(image_path, min_len)
    return [TextContent(type="text", text=result.model_dump_json(indent=2))]

# 4. Add to handler map (inside `_register_tools()`)
handler_map["extract_strings"] = _handle_extract_strings
```

### Step 3: Register in tool selector for AI (`src/agent/tool_selector.py`)

```python
# Add to your phase's tool list
PHASE_TOOLS["strings_analysis"] = [
    {"tool": "extract_strings", "priority": 1, "reasoning": "Extract embedded strings"},
]
```

That's it. The tool will appear in `findevil tools`, be callable via MCP, and be available for AI-driven workflows.

---

## 📜 License

MIT License — see [LICENSE](LICENSE).

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

<div align="center">
  <strong>FindEvil Agent v2.1.4</strong><br>
  <sub>Autonomous DFIR Analysis · Memory · Disk · Registry · Network · Carving · YARA</sub>
</div>
