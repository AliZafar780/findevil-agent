# FindEvil Agent — Comprehensive Gap Analysis Report

> **Date:** 2026-06-05  
> **Scope:** Full codebase audit of FindEvil-MemoryGraph DFIR agent  
> **Files Analyzed:** 26 source files across `src/`, `tests/`, `config/`  
> **Total Gaps Found:** 33  
> **Severity Distribution:** 🔴 5 Critical · 🟠 12 High · 🟡 10 Medium · 🟢 6 Low

---

## 🔴 CRITICAL GAPS

### GAP-01: Agent Loop Exit Criteria Broken
**File:** `src/agent/loop.py:402-410`
**Severity:** 🔴 Critical

The `_build_result()` method considers execution successful if `self.state.status == "running"`, but `status` is **never set to any completion state** — it starts as `"running"` and only changes to `"aborted"` on abort conditions. This means **every execution that doesn't abort is reported as successful**, even if every single tool call failed.

```python
def _build_result(self, report: str) -> dict:
    return {
        "success": self.state.status == "running",  # Always True unless aborted
        ...
    }
```

**Fix:** Add `self.state.status = "completed"` after all phases finish in `run()`.

---

### GAP-02: Phantom Tool Calls via Regex Fallback
**File:** `src/agent/output_parser.py:44-45`
**Severity:** 🔴 Critical

When the LLM doesn't return JSON, `parse_tool_decision()` falls back to regex-extracting tool names anywhere in the text:

```python
tool_pattern = r'\b(fs_partition_scan|fs_list_files|...)\b'
return list(set(re.findall(tool_pattern, text)))
```

If the LLM says "We already called `fs_list_files` and it failed", this returns `["fs_list_files"]` — **causing the tool to be called again**. No semantic understanding of context.

**Fix:** Only return tool names from JSON blocks, or add a semantic guard that checks for "call" verbs near the matched tool name.

---

### GAP-03: Production Memory IOC Patterns Use Test/LAN IPs
**File:** `src/tools/memory.py:52-54`
**Severity:** 🔴 Critical

The `MEMORY_IOC_PATTERNS` dictionary contains generic LAN/test IPs that will cause **guaranteed false positives** on every real investigation:

```python
"suspicious_ips": [
    b"192.168.1.100", b"10.0.0.50", b"10.0.0.1", b"127.0.0.1",  # ← 127.0.0.1 is localhost!
],
```

- `127.0.0.1` is **localhost** — present in literally every network stack
- `192.168.1.100` and `10.0.0.50` are **generic private IPs** commonly used in test environments
- The string scan finds these in any binary that contains these byte sequences, not just actual connections

**Fix:** Remove generic test IPs. Replace with real known-bad indicators (or make IOCs configurable via external feed).

---

### GAP-04: FALLBACKS Typo — Recovery Logic Completely Broken
**File:** `src/agent/loop.py:129,232`
**Severity:** 🔴 Critical

The attribute is defined as `FALLBACK_CHAINS` but accessed as `FALLBACKS`:

```python
# Line 129: Defined as
FALLBACK_CHAINS = { ... }

# Line 232: Accessed as (TYPO!)
fallbacks = self.FALLBACKS.get(tool_name, [])
#            ^^^^^^^^^^
# This ALWAYS returns [] — the entire fallback mechanism is dead code
```

This means **every tool failure is final** — no fallback tools are ever attempted, even though the entire recovery architecture was designed for it.

**Fix:** Change `self.FALLBACKS` → `self.FALLBACK_CHAINS`.

---

### GAP-05: Built-in YARA Rules Contain Test/Demo Indicators
**File:** `src/tools/patterns.py:53-63`
**Severity:** 🔴 Critical

The `NetworkIndicators` rule contains placeholder test data guaranteed to produce false positives:

```yara
rule NetworkIndicators {
    strings:
        $ip1 = "192.168.1.100:4444" nocase       # Common test IP
        $domain1 = "malware.evil.com" nocase       # Demo domain
        $url1 = "http://evil.com/payload" nocase   # Demo URL
    condition: any of them
}
```

And `SuspiciousFileExtensions` flags `.ps1`, `.vbs`, `.js`, `.bat`, `.jar` — legitimate files used in every Windows environment:

```yara
rule SuspiciousFileExtensions {
    strings:
        $e1 = ".ps1" nocase   # Every PowerShell script
        $e3 = ".js" nocase    # Every JavaScript file
        $e7 = ".bat" nocase   # Every batch file
    condition: any of them
}
```

**Fix:** Remove demo indicators. Replace `SuspiciousFileExtensions` with specific known-malicious extension patterns (e.g., double extensions, hidden extensions). Add severity metadata.

---

## 🟠 HIGH SEVERITY GAPS

### GAP-06: Synchronous subprocess.run() Blocks Async Event Loop
**File:** `src/server.py:101-153`
**Severity:** 🟠 High

The `_run_tool()` function uses `subprocess.run()` (blocking) inside async handler functions:

```python
def _run_tool(cmd: list, timeout: int = 120, ...) -> dict:
    result = subprocess.run(cmd, ...)  # BLOCKS event loop
```

This blocks the entire asyncio event loop during tool execution. With 600s timeouts on carving, this **freezes the server** for 10 minutes.

**Fix:** Replace with `asyncio.create_subprocess_exec()` + `asyncio.wait_for()`.

---

### GAP-07: No Token/Cost Tracking on LLM API
**File:** `src/agent/groq_client.py:99-115`
**Severity:** 🟠 High

The `_call_groq()` method makes API calls but **never tracks token usage**:

```python
def _call_groq(self, messages: list, temperature: float = 0.1) -> str:
    for model in models_to_try:
        response = self.client.chat.completions.create(...)
        # No usage tracking, no cost calculation, no token limits
        return response.choices[0].message.content or ""
```

With 30+ iterations and 4096 max_tokens per call, a single investigation could consume **120K+ tokens** with no safeguards.

**Fix:** Track `response.usage` (prompt_tokens, completion_tokens, total_tokens). Add cost limits and per-session token caps.

---

### GAP-08: Agent Has No API Cost Safeguards
**File:** `src/agent/loop.py:53-61`
**Severity:** 🟠 High

`AgentState` tracks max_iterations (30), consecutive_failures (5), and elapsed time (3600s), but **no financial cost limits**:

- No `max_total_tokens` cap
- No `max_api_cost` cap  
- No `max_consecutive_llm_calls` limit
- Agent could drain API quota in minutes

**Fix:** Add token budget to AgentState, enforce per-phase token limits.

---

### GAP-09: Tool Registry Is Unused by Agent Loop
**File:** `src/agent/tool_selector.py` (entire file)
**Severity:** 🟠 High

`TOOL_REGISTRY` contains 58 detailed tool entries with priorities, descriptions, and categories — but **zero code imports or uses it**:

- `tool_selector.py` is never imported in `loop.py`
- The agent relies entirely on LLM decisions → expensive, slow, unpredictable
- `suggest_next_tools()` and `get_tool_for_artifact()` are dead code
- Phase tool lists are hardcoded in `DEFAULT_TOOLS` dict inside `loop.py`

**Fix:** Integrate `tool_selector.py` into `loop.py._get_phase_tools()` as the default (non-LLM) path.

---

### GAP-10: 5 Tools Referenced in Registry Don't Exist
**File:** `src/agent/tool_selector.py:31-33,48-50`, `src/server.py`
**Severity:** 🟠 High

The tool registry references tools that are **not implemented** as MCP server tools:

| Referenced Tool | Expected Function | Status |
|---|---|---|
| `fs_get_stats` | Get filesystem metadata | ❌ Not implemented |
| `mem_scan_malware` | Scan memory for malware | ❌ Not implemented |
| `timeline_query` | Query timeline | ❌ Not implemented |
| `timeline_export` | Export timeline | ❌ Not implemented |
| `fs_stat` | Filesystem stats | ❌ Not implemented |

These create false expectations and cause "Unknown tool" errors when the LLM suggests them.

**Fix:** Either implement the missing tools or remove them from the registry.

---

### GAP-11: Three Test Files Referenced But Don't Exist
**Files:** `tests/test_cli.py`, `tests/test_forensic_tools.py`, `tests/test_groq_client.py`
**Severity:** 🟠 High

These test files are mentioned in project documentation but **do not exist on disk**. The glob search found only 6 test files:

```
Found:  test_server.py, test_workflow.py, test_edge_cases.py
Missing: test_cli.py, test_forensic_tools.py, test_groq_client.py
```

**Fix:** Either create these test files or update documentation.

---

### GAP-12: Edge Case Tests Run Manually, Not via pytest
**File:** `tests/test_edge_cases.py:412-418` (and all test files)
**Severity:** 🟠 High

All test files use manual `if __name__ == "__main__"` runners instead of pytest:

```python
def main():
    success = asyncio.run(test_all_edge_cases())
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
```

Despite `pyproject.toml` having full pytest configuration (`asyncio_mode = "auto"`, `testpaths = ["tests"]`), **`pytest` cannot discover any tests** because:
1. Tests aren't in `class Test*` or `def test_*` format discoverable by pytest
2. They use custom `check()` function instead of `assert`
3. `asyncio.run()` is called manually instead of using pytest-asyncio fixtures

**Fix:** Convert to pytest test functions with `async def test_*()` naming, use native `assert`, leverage pytest-asyncio.

---

### GAP-13: `benchmark_accuracy` Tool Is a No-Op Stub
**File:** `src/server.py:1402-1428`
**Severity:** 🟠 High

The accuracy benchmark handler returns ground truth as-is without any comparison:

```python
async def _handle_benchmark(args: dict) -> list:
    ...
    return [TextContent(type="text", text=json.dumps({
        "success": True,
        "benchmark": {
            "ground_truth": ground_truth,  # Just echoes input!
            ...
        },
        "message": "Accuracy benchmark framework ready. Run full workflow then pass findings here.",
    }))]
```

It doesn't:
- Run any analysis against the evidence
- Compare findings to ground truth
- Compute precision/recall/F1 scores
- Generate any actual benchmark metrics

**Fix:** Implement actual comparison logic: parse ground truth, run workflow, compare findings.

---

### GAP-14: Registry Handler Leaks Path Before Validation
**File:** `src/server.py:1156-1168`
**Severity:** 🟠 High

The registry handler checks file existence and leaks the **full path** before validating it's within evidence root:

```python
if not Path(hive_path).exists():
    return [TextContent(type="text", text=json.dumps({
        "success": False,
        "error": f"Registry hive not found: {hive_path}",  # PATH LEAK
    }))]
```

This creates an **oracle for file existence** outside the evidence root — an attacker can probe arbitrary paths.

**Fix:** Validate evidence path FIRST, then check existence with a generic error.

---

### GAP-15: Evidence Pre-validation Missing Before Analysis Phase
**File:** `src/agent/loop.py:180-200`
**Severity:** 🟠 High

The agent loop doesn't validate that evidence paths exist before calling tool handlers. Each of the 23 handlers validates independently, wasting time:

```
Phase starts → tool1 → handler validates path (exists!) → tool2 → handler validates path → ...
```

If the evidence doesn't exist, this requires **23 round-trips through the LLM** to fail.

**Fix:** Add `_validate_evidence()` at the start of `run()` that checks path exists, size > 0, file is readable.

---

## 🟡 MEDIUM SEVERITY GAPS

### GAP-16: `config/tools.toml` Is Not Used by Any Code
**File:** `config/tools.toml` (entire file, 64 lines)
**Severity:** 🟡 Medium

The TOML config defines tool commands, argument schemas, and types for `fls`, `icat`, `mmls`, `fsstat`, `foremost`, `bulk_extractor`, and `hashdeep` — but **no code loads this file**:

```
Tools in config/tools.toml → ❌ No code loads this
Tools in server.py → ✅ Hardcoded paths and argument construction
```

**Fix:** Load `config/tools.toml` at startup and use it to dynamically build tool commands.

---

### GAP-17: Lazy Python Imports Inside Async Handlers Add Latency
**File:** `src/server.py:1058,1082,1105,1126,1348,1370,1389`
**Severity:** 🟡 Medium

Tool imports happen inside async handler functions instead of at module top:

```python
async def _handle_mem_analyze(args: dict) -> list:
    from src.tools.memory import analyze as mem_analyze  # Import on every call!
```

Python caches imports, but the `from ... import` lookup still adds ~5-10ms per call. With 30+ tool calls per investigation, this adds up.

**Fix:** Move all imports to top of module.

---

### GAP-18: `_is_memory_capture()` Gzip Detection Too Broad
**File:** `src/server.py:1041-1053`
**Severity:** 🟡 Medium

The memory capture detection considers gzip files as valid memory captures:

```python
if header[:4] in (b'\x7fELF', b'PAGE', b'\x1f\x8b'):  # 0x1f8b = gzip
```

`0x1f8b` is the gzip magic number — any gzip-compressed file (logs, archives, packet captures) would pass this check.

**Fix:** Add additional checks for memory capture signatures beyond magic bytes.

---

### GAP-19: Carve Handler Creates Output Directory Before Full Validation
**File:** `src/server.py:819,815-817`
**Severity:** 🟡 Medium

Output directory is created before all validation checks complete:

```python
out_err = _validate_output_dir(output_dir)
if out_err:
    return ...  # Error returned, but directory already exists as empty artifact
Path(output_dir).parent.mkdir(parents=True, exist_ok=True)  # Created too early
```

If the carve fails after this point, **empty directories are left behind**.

**Fix:** Move directory creation to just before `_run_tool()`.

---

### GAP-20: All Findings Are Marked as CONFIRMED Regardless of Quality
**File:** `src/agent/loop.py:337-363`
**Severity:** 🟡 Medium

`_extract_findings()` marks everything as CONFIRMED:

```python
self.state.add_finding({
    ...
    "confidence": "CONFIRMED" if result.get("success") else "UNVERIFIED",
    # No INFERRED, no confidence scoring based on evidence quality
})
```

There's no:
- Differentiation between direct evidence vs inferred evidence
- Confidence scoring based on multiple corroborating tools
- Source reliability assessment

**Fix:** Implement confidence scoring based on: number of tools corroborating, directness of evidence, false positive likelihood.

---

### GAP-21: No Dockerfile or Containerized Deployment
**File:** (missing — no Dockerfile in project)
**Severity:** 🟡 Medium

DFIR tools (Sleuth Kit, Volatility, foremost, YARA) have complex installation requirements. Without containerization, deployment is fragile and environment-dependent.

**Fix:** Create multi-stage Dockerfile with all forensic tools pre-installed.

---

### GAP-22: Audit Log Writes Every Tool Call to Disk
**File:** `src/server.py:65-81`
**Severity:** 🟡 Medium

Audit logging writes to disk on every single tool call:

```python
def _audit_log(tool, arguments, result, duration_ms, error=None):
    _audit_entries.append(entry)
    with open(_audit_log_path, "a") as f:      # Disk I/O on every call
        f.write(json.dumps(entry) + "\n")
```

With 30+ tool calls and multiple concurrent investigations, this causes unnecessary disk I/O.

**Fix:** Buffer audit entries and flush periodically (every 10 entries or 5 seconds).

---

### GAP-23: Carve Handler Ignores foremost Return Code
**File:** `src/server.py:834-853`
**Severity:** 🟡 Medium

The carve handler always returns success even if foremost fails:

```python
result = _run_tool(cmd, timeout=600)
# result["success"] is never checked!
return [TextContent(type="text", text=json.dumps({
    "success": True,  # Always True even if forensics failed
    ...
}))]
```

**Fix:** Check `result["success"]` before returning, provide proper error on failure.

---

### GAP-24: No Mypy Compliance Despite Strict Mode in Config
**File:** `pyproject.toml:94-97`
**Severity:** 🟡 Medium

`pyproject.toml` specifies `mypy strict = true` but the codebase has:

- Functions with missing return type annotations
- Implicit `Optional` types without `None` in union
- `Any` types used where specific types should exist
- Dynamic imports without type stubs

**Fix:** Run mypy, fix violations, add type stubs for untyped dependencies.

---

### GAP-25: Tool Path Resolution Repeated ~15 Times
**File:** `src/server.py` (across all handlers)
**Severity:** 🟡 Medium

Each handler independently resolves tool paths with identical pattern:

```python
# Pattern repeated 15+ times:
tshark_paths = ["/usr/bin/tshark", "/usr/local/bin/tshark"]
tshark_cmd = next((p for p in tshark_paths if Path(p).exists()), "tshark")
```

**Fix:** Create a cached `_find_tool(name: str) -> str` function at module top.

---

## 🟢 LOW SEVERITY GAPS

### GAP-26: Output Parser's extract_json_from_text Vulnerable to Bad Input
**File:** `src/agent/output_parser.py:9-31`
**Severity:** 🟢 Low

The `extract_json_from_text()` function could match malformed or incomplete JSON:

```python
patterns = [
    r'```(?:json)?\s*\n(.*?)\n```',
    r'\{[^{}]*\}',  # Simple brace matching — fails on nested objects
]
```

The second pattern `\{[^{}]*\}` only matches objects without nested braces — it will fail on any JSON with nested dictionaries.

**Fix:** Use proper JSON extraction with balanced brace counting.

---

### GAP-27: `__init__.py` Files Are Stubs
**Files:** `src/__init__.py`, `src/agent/__init__.py`, `src/tools/__init__.py`
**Severity:** 🟢 Low

Package init files are empty/near-empty, providing no explicit exports:

```python
# src/__init__.py — empty or just comments
# No __all__, no version, no imports
```

**Fix:** Add `__all__` exports, version string, and convenient re-exports.

---

### GAP-28: Hardcoded Subdirectories for Evidence and Results
**File:** `src/server.py:1460-1463`
**Severity:** 🟢 Low

Subdirectory names are hardcoded:

```python
for sub in ('disk', 'memory', 'network', 'cases'):
    (EVIDENCE_ROOT / sub).mkdir(exist_ok=True)
```

**Fix:** Make evidence subdirectories configurable via env var or config.

---

### GAP-29: Magic Number Constants Throughout Code
**Files:** Multiple
**Severity:** 🟢 Low

Numerous magic numbers with no configuration:

- `max_packets = 100` (network.py:18)
- `max_iterations = 30` (loop.py:53)
- `MAX_OUTPUT_CHARS = 100_000` (server.py:38)
- `display_filter: str = ""` (network.py default)
- `max_size_mb: int = 100` (memory.py:76)

**Fix:** Define constants with descriptive names, make configurable via env.

---

### GAP-30: Agent Overrides groq_client Instance Without Validation
**File:** `src/agent/loop.py:140-142`
**Severity:** 🟢 Low

`DFIRWorkflow.__init__` accepts an optional Groq client but creates a new one if not provided:

```python
def __init__(self, mcp_client, groq_client=None):
    self.groq = groq_client or GroqDFIRClient()  # Could raise ValueError if no API key
```

If `GROQ_API_KEY` is not set, this raises a `ValueError` during construction — but `DFIRWorkflow` has no way to function without Groq.

**Fix:** Add graceful degradation: if no API key, use fallback tool chains only.

---

### GAP-31: Tests Spawn Real Subprocesses — No Mocking
**File:** `tests/test_server.py:20-43`
**Severity:** 🟢 Low

Tests spawn real MCP server subprocesses and run forensic tools:

```python
proc = await asyncio.create_subprocess_exec(
    self.venv_python, "-m", "src.server", ...
)
```

This means:
- Tests depend on having SIFT Workstation installed
- Tests require test evidence files on disk
- Tests can't run in CI without full forensic environment
- Failures could be environment-related, not code-related

**Fix:** Add mock layer for unit tests, keep integration tests for full environment.

---

### GAP-32: Agent Uses `windows.pslist.PsList` as Default on All Memory Dumps
**File:** `src/agent/loop.py:302`
**Severity:** 🟢 Low

```python
"mem_analyze": {"memory_path": ep, "plugin": "windows.pslist.PsList"},
```

This default plugin explicitly targets Windows memory dumps, but the analysis could be against Linux or macOS images. The tool will fail silently and fall back to string scanning.

**Fix:** Add OS detection logic or make plugin auto-select based on image magic bytes.

---

### GAP-33: `SuspiciousProcessNames` Rule Has Excessive False Positive Surface
**File:** `src/tools/patterns.py:27-41`
**Severity:** 🟢 Low

The YARA rule includes terms like `beacon`, `payload`, `keylog`, `inject`, `procdump` as suspicious strings:

```yara
$s4 = "beacon" nocase    # Matches "beacon.dll" (legitimate Apple service)
$s5 = "payload" nocase   # Matches any code with "payload" in comments
$s6 = "keylog" nocase    # Source code references to keylog
```

These are generic English words present in countless legitimate software packages.

**Fix:** Add contextual proximity conditions (e.g., require process-related keywords nearby). Add whitelist exclusions.

---

## False Positive Vector Summary

| Vector | Source | Trigger | False Positive Risk |
|--------|--------|---------|-------------------|
| `127.0.0.1` in memory IOCs | `memory.py:53` | Any binary containing `127.0.0.1` | ✅ Guaranteed every analysis |
| `192.168.1.100` in memory IOCs | `memory.py:53` | Any binary with common LAN IP | ✅ Guaranteed most analyses |
| `malware.evil.com` in YARA | `patterns.py:59` | Any file containing this demo domain | ✅ Guaranteed every scan |
| NetworkIndicators rule | `patterns.py:53-64` | Any of 4 strings | 🟠 High |
| SuspiciousFileExtensions rule | `patterns.py:80-95` | Any `.ps1`, `.vbs`, `.js`, `.bat`, `.jar` file | 🟠 High |
| SuspiciousProcessNames rule | `patterns.py:27-41` | Matches `beacon`, `payload`, `inject` in any context | 🟡 Medium |
| `_is_memory_capture` gzip check | `server.py:1046` | Any gzip file identified as memory dump | 🟡 Medium |
| Phantom tool calls via regex | `output_parser.py:44` | LLM mentions a tool name in reasoning text | 🟠 High |

---

## Error Handling Coverage Matrix

| Tool Handler | Validation | File Exists | Subprocess | Timeout | Permission | Generic |
|---|---|---|---|---|---|---|
| `fs_partition_scan` | ✅ | ✅ via validate | ✅ | ✅ | ✅ | ✅ |
| `fs_list_files` | ✅ | ✅ via validate | ✅ | ✅ | ✅ | ✅ |
| `fs_extract_file` | ✅ | ✅ via validate | ✅ | ✅ | ✅ | ✅ |
| `fs_file_metadata` | ✅ | ✅ via validate | ✅ | ✅ | ✅ | ✅ |
| `fs_filesystem_info` | ✅ | ✅ via validate | ✅ | ✅ | ✅ | ✅ |
| `carve_files` | ✅ | ✅ | ❌ ignores return code | ✅ | ✅ | ✅ |
| `scan_yara` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `verify_hash` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `list_evidence` | ✅ | ✅ | N/A | N/A | ✅ | ✅ |
| `mem_analyze` | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `mem_list_processes` | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `mem_scan_network` | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `mem_dump_cmdline` | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| `reg_analyze_hive` | ❌ path leak | ✅ (before validate) | N/A | N/A | ✅ | ✅ |
| `pcap_analyze` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `pcap_list_protocols` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `timeline_build` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `timeline_filter` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `extract_features` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `benchmark_accuracy` | ✅ | ✅ | N/A | N/A | N/A | ✅ |
| `get_audit_logs` | N/A | N/A | N/A | N/A | N/A | ✅ |

---

## Test Coverage Matrix

| Area | Test Coverage | Gaps |
|------|---------------|------|
| Server tool handlers | 11 tests (test_server.py) | 12 of 23 handlers untested |
| Agent workflow | 2 tests (test_workflow.py) | No failure/recovery tests |
| Edge cases | 50+ scenarios (test_edge_cases.py) | Manual runner, no pytest |
| CLI | ❌ No tests | test_cli.py doesn't exist |
| Groq client | ❌ No tests | test_groq_client.py doesn't exist |
| Forensic tools unit | ❌ No tests | test_forensic_tools.py doesn't exist |
| Output parser | ❌ No tests | 0 tests |
| Tool selector | ❌ No tests | 0 tests |
| Prompts | ❌ No tests | 0 tests |
| Models | ❌ No tests | 0 tests |
| **Total** | **3 test files exist** | **6 test files referenced but 3 are missing** |

---

## Implementation Plan (Priority Order)

### Phase 1 — Fix Broken Core Logic (P0)
1. **GAP-04:** Fix `FALLBACKS` → `FALLBACK_CHAINS` typo in `loop.py:232`
2. **GAP-01:** Add `self.state.status = "completed"` after all phases in `loop.py:177`
3. **GAP-02:** Fix regex-based phantom tool calls in `output_parser.py:44`  
4. **GAP-03:** Remove test IPs from `memory.py:52-54`
5. **GAP-05:** Clean demo indicators from `patterns.py:53-63`

### Phase 2 — Security & Error Handling (P1)
6. **GAP-14:** Fix registry path leak in `server.py:1160-1164`
7. **GAP-06:** Make `_run_tool` async with `create_subprocess_exec`
8. **GAP-23:** Fix carve handler to check return code
9. **GAP-18:** Tighten memory capture detection
10. **GAP-19:** Move dir creation to correct position

### Phase 3 — Performance & Architecture (P2)
11. **GAP-09:** Integrate `tool_selector.py` into agent loop
12. **GAP-10:** Implement or remove missing tools from registry
13. **GAP-17:** Move imports to module top
14. **GAP-25:** Create cached `_find_tool` function
15. **GAP-22:** Buffer audit log writes

### Phase 4 — Testing & Reliability (P2)
16. **GAP-12:** Convert edge case tests to pytest format
17. **GAP-11:** Create missing test files
18. **GAP-13:** Implement actual benchmark logic
19. **GAP-31:** Add mock layer for unit tests

### Phase 5 — Polish & Configuration (P3)
20. **GAP-07/08:** Add token/cost tracking
21. **GAP-16:** Load `config/tools.toml`
22. **GAP-21:** Create Dockerfile
23. **GAP-24:** Fix mypy violations
24. **GAP-26:** Fix JSON extraction
25. **GAP-15:** Add evidence pre-validation
