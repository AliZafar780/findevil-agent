# Changelog

All notable changes to FindEvil Agent will be documented in this file.

## [2.1.1] - 2026-06-04

### Fixed
- Memory forensics: Volatility 3 fallback to string-based IOC scanning
- Cross-platform: All hardcoded `/usr/bin/` paths replaced with `shutil.which()` 
- CLI: Added ASCII logo, rich formatting, and progress indicators
- Workflow: Fixed `_run_phase` → `run()` method in agent loop

### Added
- Cross-platform support: Windows/macOS/Linux compatibility via `tool_resolver.py`
- Synthetic memory dump: 50MB with 20 embedded IOCs for testing
- 7-layer hallucination defense in accuracy benchmarks
- CHANGELOG, CONTRIBUTING, SECURITY documentation
- GitHub Actions CI workflow

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
- 72/72 edge case tests across 12 categories
- YARA pattern matching with built-in detection rules
- PCAP analysis via tshark
- Registry analysis via regipy

## [1.0.0] - 2026-06-01

### Added
- Initial MCP server with TSK/SleuthKit wrappers
- Basic DFIR workflow agent
- Flask-style file listing and extraction
