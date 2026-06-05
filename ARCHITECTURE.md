# FindEvil Agent — Technical Architecture

> **Autonomous DFIR Analysis Agent** — 22 MCP forensic tools, Groq AI integration, deterministic fallback mode.
> Version 2.1.1

---

## 1. System Overview

```
┌──────────────────────────────────────────────────────┐
│                    FIND EVIL AGENT                     │
├──────────────────────────────────────────────────────┤
│  ┌──────────────┐   ┌──────────────┐                 │
│  │  CLI (rich)   │   │ MCP Server   │                 │
│  │  findevil     │──▶│ 22 Tools     │──▶ SIFT Tools   │
│  │  findevil     │   │ Tool Calls   │   (subprocess)  │
│  │  serve        │   │ JSON-Lines   │                 │
│  └──────────────┘   └──────┬───────┘                 │
│                            │                          │
│  ┌─────────────────────────┴──────────────────────┐   │
│  │            DFIR Workflow Engine                  │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │   │
│  │  │Triage│→│  FS   │→│Carve │→│Memory│→│Registry│  │   │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘  │   │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐           │   │
│  │  │Network││Hashing││ YARA ││Timeline│           │   │
│  │  └──────┘ └──────┘ └──────┘ └──────┘           │   │
│  └────────────────────────────────────────────────┘   │
│                            │                           │
│  ┌─────────────────────────┴──────────────────────┐   │
│  │         Tool Resolver  (cross-platform)         │   │
│  │  fls │ icat │ mmls │ foremost │ yara │ tshark   │   │
│  │  bulk_extractor │ hashdeep │ volatility3         │   │
│  └────────────────────────────────────────────────┘   │
│                            │                           │
│  ┌─────────────────────────┴──────────────────────┐   │
│  │         AI / Deterministic Mode                 │   │
│  │  ┌──────────────────┐  ┌──────────────────┐     │   │
│  │  │ Groq LLM (opt)   │  │ Deterministic     │     │   │
│  │  │ Tool selection   │  │ Tool chains       │     │   │
│  │  │ Report gen       │  │ Narrative report  │     │   │
│  │  └──────────────────┘  └──────────────────┘     │   │
│  └────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

---

## 2. Project Structure

```
findevil-agent/
├── src/
│   ├── cli.py              # Rich CLI entry point (investigate, tool, serve, check)
│   ├── server.py           # MCP server — 22 tools, audit, path validation
│   ├── models.py           # Pydantic data models
│   ├── __main__.py         # Package entry point
│   ├── agent/
│   │   ├── loop.py         # DFIR workflow engine (ReAct pattern)
│   │   ├── groq_client.py  # Groq LLM client + deterministic fallback
│   │   ├── output_parser.py # Balanced-brace JSON extraction from LLM output
│   │   ├── tool_selector.py # 58-entry tool registry with fallback chains
│   │   └── prompts.py      # DFIR system prompts
│   └── tools/
│       ├── filesystem.py    # TSK wrappers (fls, icat, mmls, fsstat, istat)
│       ├── carving.py       # Foremost carving + bulk_extractor
│       ├── memory.py        # Volatility 3 + string-based IOC fallback
│       ├── registry.py      # Regipy hive parsing
│       ├── network.py       # TShark PCAP analysis
│       ├── hashing.py       # sha256sum / md5sum / sha1sum
│       ├── patterns.py      # YARA rules (C2, crypto, webshells, PS abuse)
│       ├── timeline.py      # Plaso timeline build + filter
│       └── tool_resolver.py # Cross-platform tool resolution via shutil.which()
├── config/
│   ├── tools.toml           # Tool path & argument definitions
│   └── server.toml          # Server configuration
├── tests/
│   ├── test_cli.py          # CLI unit tests (4)
│   ├── test_forensic_tools.py # Tool model tests (15)
│   ├── test_groq_client.py  # Parser/selector/client tests (22)
│   ├── test_workflow.py     # Workflow integration tests (2)
│   ├── test_edge_cases.py   # Edge case integration tests (53)
│   └── test_server.py       # MCP server integration tests (11)
├── .github/workflows/ci.yml # GitHub Actions CI/CD
├── Dockerfile               # Multi-stage Docker build
├── pyproject.toml            # PEP 621 project config
└── GAP_ANALYSIS.md          # 33-gap audit and closure report
```

---

## 3. Key Design Decisions

### 3.1 MCP Protocol (not raw subprocess)
All 22 forensic tools are exposed via the [Model Context Protocol](https://modelcontextprotocol.io), making them available to any MCP-compatible client (Claude Code, custom agents, etc.).

### 3.2 Security First
Evidence path validation is enforced at the server level:
- All file paths are checked against `EVIDENCE_ROOT` before any tool runs
- Path traversal (`../`, null bytes) is blocked with descriptive errors
- Output directories restricted to `/results` for carve/export operations

### 3.3 Graceful Degradation
Every feature works without any external API key:
| Feature | With Groq API Key | Without |
|---------|-------------------|---------|
| Tool execution | ✅ | ✅ |
| Tool selection | AI-optimized | Deterministic fallback chains |
| Report generation | Structured JSON via LLM | Built-in narrative generator |

### 3.4 AI Parser
The `output_parser.py` module uses balanced-brace JSON extraction to handle LLM responses wrapped in markdown code blocks — robust against variations in LLM output format.

### 3.5 Deterministic Mode
When no `GROQ_API_KEY` is set, the agent uses `tool_selector.py` — a registry of 58 tool entries organized by investigation phase with priority ordering and fallback chains.

---

## 4. Data Flow

```
1. User Input
   │
   ▼
2. CLI (src/cli.py)
   │  ─ Parses args, sets up logging
   │  ─ Routes to: investigate / tool / serve / check
   ▼
3. MCP Server (src/server.py)  ←─── For `serve` mode
   │  ─ Validates evidence path
   │  ─ Routes to tool handler
   │  ─ Calls system tool via subprocess
   │  ─ Logs to audit trail
   ▼
4. System Tool (subprocess)
   │  ─ fls / icat / mmls / foremost / yara / etc.
   ▼
5. Result
   │  ─ JSON response with success, data, error, timing
   ▼
6. Workflow Loop (src/agent/loop.py)  ←─── For `investigate` mode
   │  ─ Calls tools iteratively
   │  ─ AI selects next tools (or deterministic fallback)
   │  ─ Accumulates findings
   ▼
7. Report
   │  ─ AI-generated structured report or narrative summary
```

---

## 5. Tool Resolution Strategy

Tool resolution uses a layered approach via `src/tools/tool_resolver.py`:

1. **`shutil.which()`** — Check system PATH
2. **`TOOL_LOCATIONS`** — Per-platform fallback paths (Linux/macOS/Windows)
3. **`config/tools.toml`** — User-defined custom paths (checked by `src/server.py`)

Results are cached at the server level in `_TOOL_CACHE` for the lifetime of the process.

---

## 6. Testing Strategy

| Layer | Tests | Framework |
|-------|-------|-----------|
| Unit (models, parsers, selectors) | 41 | pytest |
| Integration (MCP server, workflow) | 66 | pytest + pytest-asyncio |
| Security (path traversal, null bytes, forbidden dirs) | 30+ vectors | pytest parametrize |
| CI | 9 jobs × 4 Python versions | GitHub Actions |
| Coverage | 25% (expected — server runs as subprocess) | pytest-cov |

---

## 7. Files NOT in this project

The following files from earlier architecture drafts have been integrated directly into `src/server.py` and do not exist as separate modules:

| Old File | Responsibility | Current Location |
|----------|---------------|-----------------|
| `src/security.py` | Evidence path validation | `src/server.py` — `_validate_evidence_path()` |
| `src/audit.py` | Execution trail logging | `src/server.py` — `_log_audit()` |
| `src/utils.py` | Shared utilities | Inline in relevant modules |
| `config/server.toml` | Server configuration | Inline constants in `src/server.py` |

---

*Architecture v2.1.1 — Maintained alongside README.md*
