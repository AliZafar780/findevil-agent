<div align="center">

# FindEvil Agent

**Autonomous DFIR Analysis Agent — AI-Powered Digital Forensics & Incident Response**

[![Version](https://img.shields.io/badge/version-2.1.5-blue?style=flat-square&logo=github)](https://github.com/AliZafar780/findevil-agent)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12%20|%203.13-blue?style=flat-square&logo=python)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-173%20passing-brightgreen?style=flat-square)](https://github.com/AliZafar780/findevil-agent/actions)
[![Tools](https://img.shields.io/badge/tools-21%20MCP-informational?style=flat-square)](#mcp-server)
[![AI](https://img.shields.io/badge/AI-Groq%20%7C%20Deterministic%20Mode-orange?style=flat-square)](#ai-integration)
[![Docker](https://img.shields.io/badge/docker-multi--stage-2496ED?style=flat-square&logo=docker)](Dockerfile)
[![CI](https://img.shields.io/badge/CI-CD%20%7C%20Lint%20%7C%20Type%20Check%20%7C%20Audit-blue?style=flat-square)](.github/workflows/ci.yml)
[![Security](https://img.shields.io/badge/security-hardened-red?style=flat-square)](SECURITY.md)

`#dfir` `#incident-response` `#forensics` `#mcp` `#memory-forensics` `#yara` `#automation`

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [MCP Server](#mcp-server)
- [AI Integration](#ai-integration)
- [Security](#security)
- [Testing](#testing)
- [Configuration](#configuration)
- [Docker](#docker)
- [Project Structure](#project-structure)
- [Extending](#extending)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**FindEvil Agent** is an autonomous digital forensics and incident response (DFIR) agent that orchestrates **21 MCP forensic tools** across memory, filesystem, registry, network, and carving analysis domains. It integrates **Groq AI** for intelligent tool selection and narrative report generation, while operating fully in **deterministic mode without any API key**.

The agent follows a structured investigation workflow — triage, filesystem analysis, artifact extraction, memory analysis, registry parsing, network analysis, timeline correlation, and report generation — all orchestrated through a single CLI command.

### Key Capabilities

| Capability | Status |
|---|---|
| **21 MCP Forensic Tools** | Disk, memory, registry, network, carving, hashing, YARA |
| **AI Integration** | Groq Llama 3.3 70B (optional — deterministic fallback always works) |
| **Zero API Key Required** | All features operational without Groq, Shodan, or any external key |
| **173 Passing Tests** | Unit + Integration + Property-Based (Hypothesis) + Edge Case |
| **Security Hardened** | Path traversal, null byte injection, TOCTOU, YARA injection, command injection — all blocked |
| **Confidence Scoring** | Per-tool data quality: CONFIRMED / INFERRED / UNVERIFIED |
| **Token Budget Caps** | Max 100K tokens/session (~$0.07) with real-time tracking |
| **Graceful Degradation** | Every tool has a fallback — the system never crashes from missing dependencies |
| **Docker Support** | Multi-stage build with sleuthkit, yara, tshark, foremost, bulk-extractor |
| **CI/CD Pipeline** | GitHub Actions: lint, type-check, test (4 Python versions), build, Docker, security audit |

---

## Features

### Tool Categories

| Category | Tools | Backend |
|---|---|---|
| **Filesystem** | `fs_partition_scan`, `fs_list_files`, `fs_file_metadata`, `fs_extract_file`, `fs_filesystem_info` | TSK (fls, icat, mmls, fsstat, istat) |
| **Carving** | `carve_files` | foremost |
| **Hashing** | `verify_hash` | hashdeep / openssl |
| **YARA** | `scan_yara` | yara (built-in rules for C2 domains, crypto miners, PowerShell abuse, webshells) |
| **Memory** | `mem_list_processes`, `mem_analyze`, `mem_scan_network`, `mem_dump_cmdline` | Volatility 3 + string-based IOC fallback |
| **Registry** | `reg_analyze_hive`, `reg_list_keys`, `reg_get_value` | regipy |
| **Network** | `pcap_analyze`, `pcap_list_protocols`, `pcap_extract_streams` | tshark |
| **Info** | `list_evidence`, `get_case_info`, `export_timeline` | TSK + built-in |
| **Config** | `get_tool_config` | config/tools.toml |

### AI Integration

- **Groq Llama 3.3 70B** for intelligent tool selection and narrative report generation
- **Deterministic fallback** — no API key needed; built-in tool selector with 58-entry registry and priority-based fallback chains
- **Token budget tracking** — real-time cost monitoring (max 100K tokens/session)
- **Evidence type detection** — automatically filters incompatible tools to prevent wasted LLM calls

### Security Hardening

- Path traversal blocked (9 variants including encoded, unicode, and null-byte attacks)
- Null byte rejection on all evidence paths
- Command injection protection on YARA rules and subprocess calls
- TOCTOU race condition mitigation via `asyncio.Lock`
- Output size limits (100K chars max per tool)
- Persistent security event logging to `~/.local/share/findevil/security_events.jsonl`
- Type safety enforced by Pydantic models

### Performance Optimizations

- Lazy imports — modules loaded only when their tools are first called
- Cached tool resolution — `shutil.which()` results cached per session
- Buffered audit writes — batched disk I/O for security logging
- Module-scoped MCP server fixture cut edge case test suite from 3+ minutes to ~25 seconds

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          FindEvil Agent                                  │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐   ┌──────────────────┐   ┌─────────────────────┐ │
│  │  CLI (rich)       │   │  MCP Server      │   │  Groq AI /           │ │
│  │  findevil         │──▶│  21 Tools API    │──▶│  Deterministic       │ │
│  └──────────────────┘   └────────┬─────────┘   │  Tool Selector +     │ │
│                                  │              │  Report Generator    │ │
│  ┌───────────────────────────────┴────────────┐ └──────────┬──────────┘ │
│  │             DFIR Workflow Engine            │            │            │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────┐ │            │            │
│  │  │Triage  │→│  FS    │→│ Carve  │→│Memory│─┘            │            │
│  │  └────────┘ └────────┘ └────────┘ └──────┘              │            │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐          │            │
│  │  │Registry│→│Network │→│Hashing │→│ Timeline │          │            │
│  │  └────────┘ └────────┘ └────────┘ └──────────┘          │            │
│  └─────────────────────────────────────────────────────────┘            │
│                                  │                                       │
│  ┌───────────────────────────────┴───────────────────────────────────┐  │
│  │            Tool Resolver + Config/Tools.TOML                        │  │
│  │  fls │ icat │ mmls │ foremost │ yara │ tshark │ hashdeep           │  │
│  │  bulk_extractor │ volatility3 │ regipy │ reglookup                  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Investigation Workflow

1. **Evidence Input** — Disk images (raw, E01), memory dumps (raw, ELF), PCAPs, registry hives
2. **Triage** — Verify integrity via hashing (SHA256/SHA1/MD5), inspect filesystem metadata
3. **Filesystem Analysis** — List files, extract metadata, recover deleted content via TSK
4. **Artifact Extraction** — Carve deleted files, scan with YARA rules (C2, crypto miners, webshells, PS abuse)
5. **Memory Analysis** — List processes, scan network connections, dump command lines via Volatility 3 or IOC fallback
6. **Registry Analysis** — Parse hive files, extract keys and values via regipy
7. **Network Analysis** — Analyze PCAPs, extract protocols, reconstruct conversations via tshark
8. **Timeline Correlation** — Export MAC timelines for temporal correlation
9. **Report Generation** — Groq LLM narrative or built-in deterministic report generator

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **System Tools** (recommended for full functionality):
  ```bash
  # Linux
  sudo apt install sleuthkit foremost yara tshark

  # macOS
  brew install sleuthkit foremost yara tshark
  ```
- **Groq API Key** (optional): [Get one free](https://console.groq.com)

### Installation

```bash
# Clone the repository
git clone https://github.com/AliZafar780/findevil-agent.git
cd findevil-agent

# Create and activate virtual environment
python3 -m venv venv && source venv/bin/activate

# Install the package
pip install -e .
```

### Verify Installation

```bash
findevil check
```

### Run Your First Investigation

```bash
# Generate a test image with real IOCs
findevil create-test-image test.dd

# Run full autonomous investigation (no API key needed)
findevil investigate test.dd --output ./results

# With AI-powered analysis (requires GROQ_API_KEY)
findevil investigate test.dd --output ./results
```

---

## Usage Guide

### CLI Reference

```
findevil [command] [options]
```

| Command | Description |
|---|---|
| `investigate <evidence>` | Run full investigation workflow |
| `check` | Verify environment and tool availability |
| `tools` | List all available MCP tools |
| `tool <name> [args]` | Execute a single MCP tool directly |
| `create-test-image <path>` | Generate test disk image with embedded IOCs |
| `serve` | Start MCP server for LLM integration |

### Investigation Options

```bash
findevil investigate <evidence> [options]

Options:
  --output PATH      Output directory for results
  --task TEXT        Natural language task description
  --groq-model TEXT  Groq model (default: llama-3.3-70b-versatile)
  --no-ai            Skip AI — use deterministic report generator
  --phase PHASE      Run specific phase only (triage, fs, carve, memory, registry, network, timeline)
  --json             Output as JSON
  --debug            Enable debug logging
  --no-logo          Skip ASCII logo
```

### Usage Examples

```bash
# Full investigation with AI
findevil investigate ./evidence.dd --output ./results

# Deterministic mode (no API key required)
findevil investigate ./evidence.dd --no-ai

# Run specific phase only
findevil investigate ./evidence.dd --phase memory

# List all available tools
findevil tools

# Execute a single tool directly
findevil tool fs_list_files --image evidence.dd
findevil tool scan_yara --image evidence.dd --rules "rule Bad { strings: \$a = \"evil\" condition: \$a }"

# Investigate a directory of evidence files
findevil investigate /evidence/case_dir/ --output ./results

# Debug mode
findevil investigate ./evidence.dd --debug
```

---

## MCP Server

FindEvil implements the **Model Context Protocol** (MCP), making all 21 tools available to any MCP-compatible LLM client.

### Configuration

Add to your MCP client configuration (e.g., `claude_desktop_config.json`):

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

### Starting the Server

```bash
findevil serve
```

### Available Tools

All 21 tools are self-documenting with typed input schemas. The server exposes:

- **Filesystem**: partition scanning, file listing, metadata extraction, file extraction, filesystem info
- **Carving**: deleted file recovery via foremost
- **Hashing**: SHA256/SHA1/MD5 integrity verification
- **YARA**: pattern-based scanning with built-in IOC rules
- **Memory**: process listing, network connection scanning, command line dumping
- **Registry**: hive parsing, key/value enumeration
- **Network**: PCAP analysis, protocol extraction, stream reconstruction
- **Timeline**: MAC timeline generation and filtering
- **Utility**: evidence listing, case info, tool configuration queries

---

## AI Integration

### Groq AI Mode

With a `GROQ_API_KEY` set, the agent uses **Groq's Llama 3.3 70B** model to:

- Select the optimal next tool based on investigation context
- Generate narrative reports summarizing findings
- Prioritize investigation paths based on evidence type

```bash
export GROQ_API_KEY="your_api_key_here"
findevil investigate ./evidence.dd --output ./results
```

### Deterministic Mode (Default)

Without any API key, all features work using built-in deterministic logic:

| Feature | With API Key | Without API Key |
|---|---|---|
| Tool execution | Yes | Yes |
| Tool selection | AI-optimized | Deterministic fallback chains (58-entry registry) |
| Report generation | Groq narrative | Built-in narrative generator |
| Token tracking | Yes | Yes (capped at $0) |
| Audit trail | Yes | Yes |

### Graceful Degradation

Every forensic tool has at least one fallback path:

| Missing Tool | Fallback |
|---|---|
| YARA | Built-in signature scanning |
| Volatility 3 | String-based IOC scanning |
| TSK (sleuthkit) | Reduced file listing via Python |
| regipy | reglookup CLI (if available) |
| tshark | Basic packet analysis via Python |
| foremost | Built-in file signature carving |

---

## Security

### Defense-in-Depth Architecture

| Layer | Protection |
|---|---|
| **Path Validation** | All evidence paths validated against `EVIDENCE_ROOT` |
| **Input Sanitization** | Null bytes, control chars, and path traversal blocked (9 variants) |
| **Type Safety** | Pydantic models enforce parameter types at runtime |
| **Command Injection** | YARA rules and exec commands validated before execution |
| **TOCTOU Prevention** | `asyncio.Lock` prevents race conditions on concurrent access |
| **Output Isolation** | Tool output limited to 100K chars maximum |
| **Timeout Bounds** | Tool execution capped at 600 seconds |
| **Audit Trail** | Every tool call logged with arguments, result, and timing; persisted to JSONL |

### Attack Vectors Blocked

- Path traversal (9 encoding variants)
- Null byte injection
- Symlink swap attacks (TOCTOU)
- Output directory escape (10 system directories)
- Command injection via YARA rules and exec parameters
- Wrong parameter types and missing required parameters
- Empty YARA rules and malformed input
- Resource exhaustion (200MB+ input)
- Log injection via crafted arguments
- Concurrent access race conditions

### Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

---

## Testing

### Run the Test Suite

```bash
# All tests
pytest tests/ -v

# Specific test suites
pytest tests/test_cli.py -v              # CLI tests
pytest tests/test_forensic_tools.py -v   # Tool model & resolver tests
pytest tests/test_groq_client.py -v      # Parser, selector, client tests
pytest tests/test_server.py -v           # MCP server integration tests
pytest tests/test_edge_cases.py -v       # Edge case integration tests
pytest tests/test_workflow.py -v         # Workflow tests
```

### Test Coverage — 173 Tests

| Suite | Type | Count | Coverage |
|---|---|---|---|
| CLI | Unit | 4 | Logo rendering, version, help, imports |
| Forensic Tools | Unit | 15 | Models (hash, pattern, filesystem, registry, network, timeline, memory), tool resolver |
| Groq Client | Unit | 22 | Client init, output parser, tool selector, fallback chains |
| Workflow | Integration | 2 | Agent loop phases, tool chaining |
| Edge Cases | Integration | 104 | Path traversal, missing evidence, carving security, YARA, large files, audit trail, concurrent access, error quality, wrong-tool rejection |
| Property-Based | Hypothesis | 15 | Tool resolver invariants, sanitize/truncate properties, all Pydantic model checks |
| Server | Integration | 11 | Tool execution, hash verification, evidence listing, path validation, error handling |

### CI Pipeline

GitHub Actions runs across **4 Python versions** (3.10, 3.11, 3.12, 3.13):

```
lint (ruff) → type-check (mypy) → test (pytest × 4 versions)
  → build (wheel) → Docker (multi-stage) → audit (pip-audit)
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | — | Groq API key (optional — all features work without it) |
| `EVIDENCE_ROOT` | `/evidence` | Default evidence directory |
| `RESULTS_ROOT` | `/results` | Default results directory |

### Optional Dependencies

```bash
# Install core forensic tools (Volatility 3, Regipy)
pip install -e ".[core]"

# Everything for development
pip install -e ".[dev,core]"
```

### Tool Configuration (`config/tools.toml`)

Tool paths and arguments are defined in `config/tools.toml`:

```toml
[tools.fls]
path = "fls"
args = ["-r", "-p", "{image_path}"]
description = "List file names in a disk image"
```

Query tool configuration at runtime:

```bash
findevil tool get_tool_config --tool fls
```

---

## Docker

### Build

```bash
docker build -t findevil-agent .
```

### Run

```bash
docker run --rm \
  -v /path/to/evidence:/evidence \
  -v /path/to/results:/results \
  findevil-agent investigate /evidence/case.dd
```

The multi-stage Dockerfile uses a `python:3.11-slim` builder and `ubuntu:24.04` runtime with sleuthkit, foremost, yara, tshark, and bulk-extractor pre-installed.

---

## Project Structure

```
findevil-agent/
├── src/
│   ├── cli.py                   # Rich CLI entry point
│   ├── server.py                # MCP server (21 tools, async subprocess, audit, security logs)
│   ├── models.py                # Pydantic data models
│   ├── _version.py              # Version constant
│   ├── __main__.py              # Package entry point
│   ├── agent/
│   │   ├── loop.py              # DFIR workflow + evidence pre-validation
│   │   ├── groq_client.py       # Groq LLM + deterministic fallback
│   │   ├── output_parser.py     # Balanced-brace JSON extraction
│   │   └── tool_selector.py     # 58-entry registry with fallback chains
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
│   ├── conftest.py              # Shared fixtures (module-scoped MCP server)
│   ├── helpers.py               # Shared test utilities
│   ├── test_cli.py              # CLI unit tests
│   ├── test_forensic_tools.py   # Tool model tests
│   ├── test_groq_client.py      # Parser/selector/client tests
│   ├── test_server.py           # MCP server integration tests
│   ├── test_edge_cases.py       # Edge case integration tests
│   └── test_workflow.py         # Workflow tests
├── scripts/
│   └── generate_test_evidence.sh  # Test evidence image generator
├── .github/workflows/ci.yml     # GitHub Actions CI/CD
├── Dockerfile                   # Multi-stage Docker build
├── pyproject.toml               # PEP 621 project config
├── CHANGELOG.md                 # Version history
└── GAP_ANALYSIS.md              # 33-gap audit and closure report
```

---

## Extending: Adding a New Forensic Tool

### Step 1: Write the tool logic

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

### Step 2: Register in the MCP server

```python
# In src/server.py
from src.tools.strings import extract_strings, StringsResult

# Add Tool definition
Tool(
    name="extract_strings",
    description="Extract ASCII/Unicode strings from a binary file",
    inputSchema={
        "type": "object",
        "properties": {
            "image_path": {"type": "string"},
            "min_length": {"type": "integer", "description": "Minimum string length", "default": 6},
        },
        "required": ["image_path"],
    },
)

# Add handler
async def _handle_extract_strings(args: dict) -> list[TextContent]:
    image_path = args["image_path"]
    min_len = args.get("min_length", 6)
    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    result = extract_strings(image_path, min_len)
    return [TextContent(type="text", text=result.model_dump_json(indent=2))]
```

### Step 3: Register in tool selector

```python
# In src/agent/tool_selector.py
PHASE_TOOLS["strings_analysis"] = [
    {"tool": "extract_strings", "priority": 1, "reasoning": "Extract embedded strings"},
]
```

That's it. The tool appears in `findevil tools`, is callable via MCP, and is available for AI-driven workflows.

---

## FAQ

### What image formats are supported?

Raw/dd images (`.dd`, `.raw`, `.img`, `.bin`), split raw images, E01/EWF (Expert Witness), and AFF4. Memory dumps: raw (`.raw`, `.mem`, `.bin`) and ELF (LiME output). PCAP/PCAPNG for network captures.

### How large can evidence files be?

Tested up to 50 GB raw images. The system uses streaming reads for carving and scans only the first 100 MB of large memory dumps for IOC strings.

### Can I analyze multiple evidence files at once?

Yes — pass a directory to `findevil investigate`. The system runs triage on each file and processes them sequentially, merging results into one timeline and report.

### Does the AI mode require internet access?

Yes — the Groq API needs internet connectivity. Deterministic mode works fully offline with no API key.

### How are Volatility plugins selected?

The system tries `linux.pslist.PsList`, `linux.malfind.Malfind`, `linux.netstat.Netstat`, `linux.bash.Bash` depending on the tool called. If none work, it falls back to string-based IOC scanning.

### What happens when a forensic tool isn't installed?

Every tool has a graceful fallback: missing YARA → built-in signature scanning, missing Volatility → string IOC scanning, missing TSK → reduced file listing, missing regipy → reglookup CLI (if available). The system never crashes from a missing tool.

### Why does `pip install -e .` not install Volatility/Regipy?

Those are in the optional `core` group. Install them explicitly: `pip install -e ".[core]"`.

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `Tool not found` | Forensic tool not installed | `sudo apt install sleuthkit foremost yara tshark` (Linux) |
| `No partition table found` | Image is a raw filesystem (no MBR/GPT) | Use `fs_filesystem_info` instead, or pass `--offset 0` |
| `Not a Registry hive file` | Wrong tool for evidence type | Use `fs_list_files` first to identify the evidence type |
| `AI returned no tools` | Parser couldn't extract JSON from LLM | Falls back to deterministic mode automatically |
| `Image contains no files` | Wrong offset or corrupted image | Run `fs_partition_scan` first, then use the detected offset |
| `HAS_EVIDENCE=False` / tests skipped | No test image | Run `findevil create-test-image /evidence/cases/test.raw` |

### Still stuck?

```bash
# Check your environment
findevil check

# Run with debug logging
findevil investigate ./evidence.dd --debug
```

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Key areas for contribution:
- macOS and Windows Volatility 3 plugins
- Additional YARA rule sets
- New forensic tool integrations
- Performance optimizations

---

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">
  <strong>FindEvil Agent v2.1.5</strong><br>
  <sub>Autonomous DFIR Analysis · Memory · Disk · Registry · Network · Carving · YARA</sub>
  <br><br>
  <sub>Built by <a href="https://github.com/AliZafar780">Ali Zafar</a></sub>
</div>
