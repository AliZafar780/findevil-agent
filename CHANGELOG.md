# Changelog

All notable changes to FindEvil Agent will be documented in this file.

## [2.1.1] - 2026-06-05

### Production Hardening — 33 Gaps Closed

#### Critical Logic Fixes
- Agent exit criteria: `status="completed"` now properly terminates the loop
- Phantom tool calls: regex requires `action:` prefix before tool names
- `FALLBACKS` → `FALLBACK_CHAINS` typo corrected in tool_selector
- Memory IOCs: replaced test IPs with real C2 indicators (Emotet, Trickbot, Conti, Dridex)
- YARA rules: cleaned demo domains, added severity metadata for all built-in rules

#### Security Hardening
- `_run_tool` converted to async via `run_in_executor` for thread safety
- Registry path oracle: validate path exists before checking registry structure
- Memory capture detection tightened (size + ELF type header checks)
- Carve directory creation moved after path validation
- Added carve return code validation

#### Performance
- `tool_selector.py` integrated into agent loop as deterministic fallback
- 5 non-existent tools removed from tool registry
- All lazy imports moved to module top
- Cached `_find_tool()` centralized function
- Audit trail writes buffered with periodic flush (every 10 entries)

#### New Tests (41)
- `test_cli.py`: CLI logo, version, help rendering (4 tests)
- `test_forensic_tools.py`: Hashing, pattern, filesystem, registry, memory, network, timeline models, tool resolver (15 tests)
- `test_groq_client.py`: Client init, output parser (JSON extraction, tool decisions, reports), tool selector (suggestions, fallback chains) — 22 tests
- Benchmark accuracy comparison with precision/recall/F1 scoring

#### Graceful Degradation
- GroqDFIRClient never crashes without API key — sets `available=False`
- All methods return empty/fallback values
- `generate_report` falls back to built-in narrative report generator
- Agent runs fully in deterministic mode without any LLM

#### Token Tracking & Budget Caps
- Real-time token tracking at $0.00059/1K input, $0.00079/1K output
- Hard cap at 100K total tokens per session (~$0.07 max cost)

#### CI/CD
- GitHub Actions: 5 jobs (lint, type-check, test ×4 Python versions, build, Docker, security audit)

#### Confidence Scoring
- Per-tool data-quality scoring: CONFIRMED / INFERRED / UNVERIFIED
- Tool-specific thresholds (match counts, file sizes, result lengths)

#### Evidence Validation
- Evidence pre-check at loop start: exists, non-empty, readable
- Aborts immediately with clear error if missing

#### Config/Tools Integration
- `config/tools.toml` loaded at server startup via `tomllib`/`tomli`
- `_find_tool()` checks TOML first as canonical source of truth
- New `get_tool_config` MCP tool for runtime query

#### Polish
- Professional DFIR-themed ASCII art logo (boxed shadow-text)
- Multi-stage Dockerfile (`python:3.11-slim` → `ubuntu:24.04`)
- Balanced-brace JSON extraction in output_parser
- `list[TextContent]` return types on all 22 async handler functions
- `.mypy_cache` excluded from git tracking

## [2.1.0] - 2026-06-03

### Security
- 20 adversarial attack vectors blocked (path traversal, null byte, symlink, injection, etc.)
- All validation in Python code — not prompt-based
- `asyncio.Lock` for concurrent call safety

### Added
- 21 MCP tools across 8 forensic categories
- Groq AI integration for autonomous tool selection
- Audit trail system (JSONL logging)
- Synthetic evidence: disk (ext2), memory (ELF), network (PCAP)
- Architecture diagrams (SVG + PNG)

## [2.0.0] - 2026-06-02

### Added
- Production CLI with 6 commands
- YARA pattern matching with built-in detection rules
- PCAP analysis via tshark
- Registry analysis via regipy

## [1.0.0] - 2026-06-01

### Added
- Initial MCP server with TSK/SleuthKit wrappers
- Basic DFIR workflow agent
