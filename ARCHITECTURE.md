# FIND EVIL! — Technical Architecture & Starter Code

> **Production-grade MCP server + self-correcting agent loop for DFIR automation**
> Based on Custom MCP Server (Approach 2) + Direct Agent Extension (Approach 1)

---

## 1. SYSTEM ARCHITECTURE

```
                    ┌─────────────────────────────────────────┐
                    │          CLAUDE CODE / OPENCLAW          │
                    │         (Or any MCP Client)              │
                    └──────────────────┬──────────────────────┘
                                       │ MCP Protocol (STDIO)
                                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                  FIND EVIL! MCP SERVER                            │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  fastmcp.FastMCP (Python)                                    │ │
│  │                                                              │ │
│  │  Tools:                    Resources:      Prompts:          │ │
│  │  ├── fs_list_files()       ├── evidence://  ├── triage_flow  │ │
│  │  ├── fs_extract_file()     └── results://   └── deep_dive    │ │
│  │  ├── fs_partition_scan()                                   │ │
│  │  ├── mem_analyze()          Middleware:                      │ │
│  │  ├── mem_list_processes()   ├── audit_logging               │ │
│  │  ├── timeline_build()       ├── evidence_integrity           │ │
│  │  ├── timeline_filter()      └── error_recovery              │ │
│  │  ├── carve_files()                                          │ │
│  │  ├── extract_features()                                     │ │
│  │  ├── reg_query()                                            │ │
│  │  ├── pcap_analyze()                                         │ │
│  │  ├── scan_yara()                                            │ │
│  │  └── verify_hash()                                          │ │
│  └──────────────────────────────────────────────────────────────┘
│                              │
│              ┌───────────────┴───────────────┐
│              ▼                               ▼
│    ┌──────────────────┐           ┌──────────────────┐
│    │   SIFT CLI Tools  │           │   Audit Trail    │
│    │   (subprocess)    │           │   (JSON Lines)   │
│    │   fls, icat,      │           │   timestamp,      │
│    │   volatility,     │           │   tool, args,     │
│    │   plaso, etc.     │           │   stdout, stderr, │
│    └──────────────────┘           │   exit_code,      │
│                                    │   duration        │
│                                    └──────────────────┘
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. PROJECT STRUCTURE

```
findevil-agent/
├── pyproject.toml              # Project metadata + dependencies
├── README.md                   # Try-It-Out instructions
├── LICENSE                     # MIT
├── ARCHITECTURE.md             # Architecture diagram + explanation
│
├── src/
│   ├── __init__.py
│   │
│   ├── server.py               # FastMCP app entrypoint
│   │
│   ├── tools/                  # MCP tool implementations
│   │   ├── __init__.py
│   │   ├── filesystem.py       # fls, icat, istat, fsstat, mmls
│   │   ├── memory.py           # volatility3 wrappers
│   │   ├── timeline.py         # log2timeline, psort
│   │   ├── carving.py          # foremost, bulk_extractor
│   │   ├── registry.py         # reglookup, regipy
│   │   ├── network.py          # tshark, tcpdump analysis
│   │   ├── hashing.py          # hashdeep, md5deep
│   │   └── patterns.py         # yara scanning
│   │
│   ├── agent/                  # Self-correcting agent loop
│   │   ├── __init__.py
│   │   ├── loop.py             # ReAct pattern implementation
│   │   ├── prompts.py          # DFIR system prompts
│   │   ├── tool_selector.py    # Intelligent tool selection
│   │   └── output_parser.py    # Structured result extraction
│   │
│   ├── security.py             # Evidence integrity enforcement
│   ├── audit.py                # Execution trace logging
│   ├── models.py               # Pydantic data models
│   └── utils.py                # Shared utilities
│
├── config/
│   ├── server.toml             # Evidence paths, timeouts, settings
│   └── tools.toml              # Tool definitions + schemas
│
├── tests/
│   ├── test_tools.py           # Individual tool tests
│   ├── test_agent.py           # Agent loop tests
│   ├── test_security.py        # Evidence integrity tests
│   └── fixtures/               # Small test images
│
├── docs/
│   ├── architecture.md         # Architecture explanation
│   ├── accuracy_report.md      # Self-assessment template
│   └── dataset_documentation.md # Evidence source docs
│
└── scripts/
    ├── setup.sh                # Environment setup
    └── run_agent.sh            # Launch agent against evidence
```

---

## 3. CORE IMPLEMENTATION

### 3.1 Server Entrypoint — `src/server.py`

```python
"""
findevil-agent: Autonomous DFIR MCP Server
Connects LLM agents to SIFT Workstation forensic tools via MCP.
"""
import json, logging, os
from pathlib import Path
from fastmcp import FastMCP
from src.tools import filesystem, memory, timeline, carving, registry, network, hashing, patterns
from src.security import EvidenceGuard
from src.audit import AuditLogger

# ── Configuration ──────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("findevil-server")

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/evidence"))
RESULTS_ROOT = Path(os.environ.get("RESULTS_ROOT", "/results"))

# ── MCP Server ─────────────────────────────────────────────────────
mcp = FastMCP(
    "findevil-agent",
    version="1.0.0",
    description="Autonomous DFIR analysis agent — MCP interface to SIFT Workstation",
)

# ── Security & Audit ───────────────────────────────────────────────
guard = EvidenceGuard(EVIDENCE_ROOT)
audit = AuditLogger(RESULTS_ROOT / "audit.log")

# ── Register Tools ─────────────────────────────────────────────────

# File System Analysis
@mcp.tool(description="List files in a forensic image using TSK fls")
def fs_list_files(image_path: str, offset: int = 0, inode: int = None) -> str:
    """List files and directories in a volume or image."""
    guard.assert_safe_path(image_path)
    result = filesystem.list_files(image_path, offset, inode)
    audit.log("fs_list_files", {"image_path": image_path, "offset": offset, "inode": inode}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

@mcp.tool(description="Extract file content by inode using TSK icat")
def fs_extract_file(image_path: str, inode: int, output_path: str = None) -> str:
    """Extract file content from a forensic image by inode number."""
    guard.assert_safe_path(image_path)
    result = filesystem.extract_file(image_path, inode, output_path)
    audit.log("fs_extract_file", {"image_path": image_path, "inode": inode}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

@mcp.tool(description="Scan partition table using mmls")
def fs_partition_scan(image_path: str) -> str:
    """Extract partition layout from a disk image."""
    guard.assert_safe_path(image_path)
    result = filesystem.scan_partitions(image_path)
    audit.log("fs_partition_scan", {"image_path": image_path}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

@mcp.tool(description="Get file system metadata using fsstat")
def fs_get_stats(image_path: str, offset: int = 0) -> str:
    """Get detailed file system metadata."""
    guard.assert_safe_path(image_path)
    result = filesystem.get_fs_stats(image_path, offset)
    audit.log("fs_get_stats", {"image_path": image_path, "offset": offset}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

# Memory Analysis
@mcp.tool(description="Analyze memory capture with Volatility 3")
def mem_analyze(memory_path: str, plugin: str = "windows.pslist.PsList") -> str:
    """Run a Volatility 3 plugin on a memory capture."""
    guard.assert_safe_path(memory_path)
    result = memory.analyze(memory_path, plugin)
    audit.log("mem_analyze", {"memory_path": memory_path, "plugin": plugin}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

@mcp.tool(description="List processes from memory capture")
def mem_list_processes(memory_path: str) -> str:
    """Extract active process list from memory."""
    guard.assert_safe_path(memory_path)
    result = memory.list_processes(memory_path)
    audit.log("mem_list_processes", {"memory_path": memory_path}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

@mcp.tool(description="Scan for malware signatures in memory")
def mem_scan_malware(memory_path: str, yara_rules: str = None) -> str:
    """Scan memory for malicious patterns using YARA."""
    guard.assert_safe_path(memory_path)
    result = memory.scan_malware(memory_path, yara_rules)
    audit.log("mem_scan_malware", {"memory_path": memory_path}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

# Timeline Analysis
@mcp.tool(description="Build forensic timeline using log2timeline/plaso")
def timeline_build(source_path: str, output_path: str = None) -> str:
    """Create a super timeline from evidence using Plaso."""
    guard.assert_safe_path(source_path)
    result = timeline.build(source_path, output_path)
    audit.log("timeline_build", {"source_path": source_path}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

@mcp.tool(description="Filter Plaso timeline using psort")
def timeline_filter(storage_path: str, query: str = "", output_format: str = "json") -> str:
    """Filter and export a Plaso timeline."""
    guard.assert_safe_path(storage_path)
    result = timeline.filter(storage_path, query, output_format)
    audit.log("timeline_filter", {"storage_path": storage_path, "query": query}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

# File Carving
@mcp.tool(description="Carve files from disk image using foremost")
def carve_files(image_path: str, file_types: str = "all", output_dir: str = None) -> str:
    """Carve deleted files from disk image based on headers."""
    guard.assert_safe_path(image_path)
    result = carving.carve_files(image_path, file_types, output_dir)
    audit.log("carve_files", {"image_path": image_path, "file_types": file_types}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

@mcp.tool(description="Extract features using bulk_extractor")
def extract_features(image_path: str, scanners: str = "all") -> str:
    """Extract emails, URLs, credit cards, and other features."""
    guard.assert_safe_path(image_path)
    result = carving.extract_features(image_path, scanners)
    audit.log("extract_features", {"image_path": image_path, "scanners": scanners}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

# Registry Analysis
@mcp.tool(description="Query Windows Registry hive")
def reg_query(hive_path: str, key: str = "/", recursive: bool = False) -> str:
    """Query a Windows Registry hive file."""
    guard.assert_safe_path(hive_path)
    result = registry.query(hive_path, key, recursive)
    audit.log("reg_query", {"hive_path": hive_path, "key": key}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

# Network Analysis
@mcp.tool(description="Analyze PCAP file with tshark")
def pcap_analyze(pcap_path: str, display_filter: str = "", max_packets: int = 1000) -> str:
    """Analyze a network capture file."""
    guard.assert_safe_path(pcap_path)
    result = network.analyze(pcap_path, display_filter, max_packets)
    audit.log("pcap_analyze", {"pcap_path": pcap_path}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

# Pattern Matching
@mcp.tool(description="Scan file with YARA rules")
def scan_yara(target_path: str, rules_path: str = None, rules_content: str = None) -> str:
    """Scan a file or directory with YARA rules."""
    guard.assert_safe_path(target_path)
    result = patterns.scan_yara(target_path, rules_path, rules_content)
    audit.log("scan_yara", {"target_path": target_path}, result)
    return json.dumps({"success": True, "data": result.model_dump()})

# Hashing
@mcp.tool(description="Compute file hashes")
def verify_hash(target_path: str, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of evidence files."""
    guard.assert_safe_path(target_path)
    result = hashing.compute_hash(target_path, algorithm)
    audit.log("verify_hash", {"target_path": target_path, "algorithm": algorithm}, result)
    return json.dumps({"success": True, "data": result.model_dump()})


# ── Resources ──────────────────────────────────────────────────────
@mcp.resource("evidence://{path}")
def get_evidence(path: str) -> str:
    """Browse available evidence files. Lists directory contents or shows file metadata."""
    full_path = EVIDENCE_ROOT / path
    guard.assert_safe_path(str(full_path))
    if full_path.is_dir():
        files = [{"name": f.name, "size": f.stat().st_size, "modified": f.stat().st_mtime}
                 for f in full_path.iterdir()]
        return json.dumps({"path": str(full_path), "type": "directory", "contents": files})
    else:
        stat = full_path.stat()
        return json.dumps({"path": str(full_path), "type": "file",
                          "size": stat.st_size, "modified": stat.st_mtime,
                          "hash": hashing.compute_hash(str(full_path), "sha256").model_dump()})


# ── Prompts ────────────────────────────────────────────────────────
@mcp.prompt(description="Initial triage workflow for new evidence")
def triage_flow(evidence_type: str = "disk") -> str:
    return f"""You are a senior DFIR analyst performing initial triage on {evidence_type} evidence.

FOLLOW THIS WORKFLOW:
1. First, examine the evidence structure (partition table, file system)
2. Build a timeline of activity
3. Extract key artifacts (recent files, browser data, registry)
4. Cross-reference findings for consistency
5. Report findings with confidence levels

SELF-CORRECTION RULES:
- If a tool returns no results, try an alternative approach
- If output is too large, filter and summarize before continuing
- If a tool fails, check the error and retry with different parameters
- If findings contradict, investigate before reporting
"""


# ── Main ───────────────────────────────────────────────────────────
def main():
    logger.info("Starting findevil-agent MCP server")
    logger.info(f"Evidence root: {EVIDENCE_ROOT}")
    logger.info(f"Results root: {RESULTS_ROOT}")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
```

### 3.2 Security Module — `src/security.py`

```python
"""
Evidence Integrity Enforcement
Prevents accidental or malicious modification of original evidence.
Architectural guardrail — enforced at MCP server level.
"""
from pathlib import Path
from typing import List

class EvidenceIntegrityError(Exception):
    """Raised when an operation would violate evidence integrity."""
    pass

class EvidenceGuard:
    """Ensures all file operations are safe and evidence is read-only."""

    def __init__(self, evidence_root: Path):
        self.evidence_root = evidence_root.resolve()
        self.allowed_paths: List[Path] = [self.evidence_root]
        self.read_only = True  # Core principle

    def assert_safe_path(self, path: str) -> Path:
        """Validate that a path is within allowed evidence directories."""
        resolved = Path(path).resolve()

        # Check if path is within evidence root
        if not any(str(resolved).startswith(str(allowed))
                   for allowed in self.allowed_paths):
            raise EvidenceIntegrityError(
                f"Path {path} is outside allowed evidence directory {self.evidence_root}"
            )

        # Check if path exists
        if not resolved.exists():
            raise EvidenceIntegrityError(f"Path does not exist: {path}")

        return resolved

    def assert_write_safe(self, path: str) -> Path:
        """Check if a path is safe for writing results."""
        resolved = Path(path).resolve()
        # Results can only be written to results/ subdirectory
        if not str(resolved).startswith(str(self.evidence_root / "results")):
            raise EvidenceIntegrityError(
                f"Cannot write to {path}: only results/ directory is writable"
            )
        return resolved

    def add_evidence_path(self, path: str):
        """Register an additional evidence mount point."""
        resolved = Path(path).resolve()
        if not resolved.exists():
            raise EvidenceIntegrityError(f"Evidence path does not exist: {path}")
        self.allowed_paths.append(resolved)

    @staticmethod
    def get_tool_restrictions() -> dict:
        """Return restrictions for tool execution."""
        return {
            "forbidden_args": ["--output", "-w", "--write", "dd", "rm", "mkfs"],
            "forbidden_commands": ["dd", "mkfs", "fdisk", "format"],
            "max_timeout": 600,  # 10 minutes max
            "max_output_size": 100_000,  # Truncate tool output
        }
```

### 3.3 Audit Module — `src/audit.py`

```python
"""
Execution Trail Audit Logging
Every tool call, its arguments, output, and result are logged.
Provides full traceability for Criterion 5 (Audit Trail).
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("findevil-audit")

class AuditLogger:
    """Structured JSON-line audit logger for full execution traceability."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def log(self, tool_name: str, arguments: dict, result: Any,
            error: Optional[str] = None, duration_ms: Optional[int] = None):
        """Log a tool execution event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self._session_id,
            "tool": tool_name,
            "arguments": arguments,
            "error": error,
            "duration_ms": duration_ms,
        }

        # Include result summary (never full raw output to avoid bloat)
        if hasattr(result, "model_dump"):
            data = result.model_dump()
            entry["result_summary"] = {
                "success": data.get("success", True),
                "count": len(data.get("data", []) if isinstance(data.get("data"), list) else []),
            }
        else:
            entry["result_summary"] = {"success": True}

        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def get_session_logs(self) -> list:
        """Retrieve all audit entries for current session."""
        if not self.log_path.exists():
            return []
        entries = []
        with open(self.log_path) as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if entry.get("session_id") == self._session_id:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue
        return entries

    def export_for_submission(self, output_path: Path):
        """Export audit logs in submission-required format."""
        entries = self.get_session_logs()
        with open(output_path, "w") as f:
            json.dump({
                "session_id": self._session_id,
                "total_calls": len(entries),
                "tools_used": list(set(e["tool"] for e in entries)),
                "entries": entries,
            }, f, indent=2)
```

### 3.4 File System Tools — `src/tools/filesystem.py`

```python
"""
File System Analysis Tools
Wraps TSK (The Sleuth Kit) commands via subprocess.
"""
import json, subprocess, tempfile
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field

# ── Data Models ────────────────────────────────────────────────────

class Partition(BaseModel):
    slot: int = Field(..., description="Partition slot number")
    start: int = Field(..., description="Start sector")
    end: int = Field(..., description="End sector")
    length: int = Field(..., description="Length in sectors")
    description: str = Field(..., description="Partition type description")

class FileEntry(BaseModel):
    name: str = Field(..., description="File or directory name")
    inode: int = Field(..., description="Inode number")
    type: str = Field(..., description="File type (d, f, r, etc.)")
    size: Optional[int] = Field(None, description="File size in bytes")
    meta_flags: Optional[str] = Field(None, description="Metadata flags")

class InodeInfo(BaseModel):
    inode: int
    mode: str
    uid: int
    gid: int
    size: int
    atime: str
    mtime: str
    ctime: str
    crtime: str
    num_links: int

class FsStats(BaseModel):
    fs_type: str
    block_size: int
    block_count: int
    volume_name: Optional[str] = None
    details: str = ""

class FileSystemResult(BaseModel):
    success: bool = True
    data: list = []
    error: Optional[str] = None

# ── Tool Implementations ───────────────────────────────────────────

SLEUTHKIT_BIN = "/usr/bin"

def _run_tsk(tool: str, args: List[str], timeout: int = 120) -> str:
    """Run a TSK tool and return stdout."""
    cmd = [f"{SLEUTHKIT_BIN}/{tool}"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(f"{tool} failed: {result.stderr}")
        return result.stdout
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"{tool} timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError(f"{tool} not found at {SLEUTHKIT_BIN}/{tool}")

def list_files(image_path: str, offset: int = 0, inode: Optional[int] = None) -> FileSystemResult:
    """List files using fls."""
    try:
        args = ["-r"] if inode else []
        if offset:
            args.extend(["-o", str(offset)])
        args.append(image_path)
        if inode is not None:
            args.append(str(inode))

        output = _run_tsk("fls", args)
        entries = []
        for line in output.strip().split("\n"):
            if line.startswith("r/r") or line.startswith("d/d") or \
               line.startswith("l/l") or line.startswith("-/r"):
                parts = line.split()
                if len(parts) >= 2:
                    entries.append(FileEntry(
                        name=line[line.rindex(" ")+1:] if " " in line else line,
                        type=parts[0][0],
                    ).model_dump())
        return FileSystemResult(data=entries)
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))

def extract_file(image_path: str, inode: int, output_path: Optional[str] = None) -> FileSystemResult:
    """Extract file using icat."""
    try:
        args = [image_path, str(inode)]
        data = _run_tsk("icat", args)

        if output_path:
            Path(output_path).write_bytes(data.encode("latin-1"))
            return FileSystemResult(data=[{
                "inode": inode, "extracted_to": output_path, "size": len(data)
            }])
        else:
            return FileSystemResult(data=[{
                "inode": inode, "size": len(data),
                "preview": data[:1000] + ("..." if len(data) > 1000 else "")
            }])
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))

def scan_partitions(image_path: str) -> FileSystemResult:
    """Scan partitions using mmls."""
    try:
        output = _run_tsk("mmls", [image_path])
        partitions = []
        for line in output.strip().split("\n"):
            if line and line[0].isdigit():
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        partitions.append(Partition(
                            slot=int(parts[0]),
                            start=int(parts[1]),
                            end=int(parts[2]),
                            length=int(parts[3]),
                            description=" ".join(parts[4:]),
                        ).model_dump())
                    except (ValueError, IndexError):
                        continue
        return FileSystemResult(data=partitions)
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))

def get_fs_stats(image_path: str, offset: int = 0) -> FileSystemResult:
    """Get file system stats using fsstat."""
    try:
        args = ["-o", str(offset), image_path] if offset else [image_path]
        output = _run_tsk("fsstat", args)
        return FileSystemResult(data=[{"raw_output": output[:5000]}])
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))

# Alias for external use
def analyze_partition_table(*args, **kwargs):
    return scan_partitions(*args, **kwargs)

def get_directory_listing(*args, **kwargs):
    return list_files(*args, **kwargs)
```

### 3.5 Agent Loop — `src/agent/loop.py`

```python
"""
Self-Correcting Agent Loop
ReAct (Reasoning + Action + Observation) pattern for DFIR analysis.
Features intelligent tool selection, self-correction, and audit logging.
"""
import json, logging, time
from datetime import datetime, timezone
from typing import List, Optional, Callable, Any

logger = logging.getLogger("findevil-agent")

class AgentState:
    """Track agent execution state for self-correction."""

    def __init__(self, max_iterations: int = 20):
        self.iteration = 0
        self.max_iterations = max_iterations
        self.tool_calls = []
        self.failures = 0
        self.consecutive_failures = 0
        self.findings = []
        self.errors = []
        self.start_time = time.time()

    def record_tool_call(self, tool: str, args: dict, result: Any, success: bool, duration: float):
        self.tool_calls.append({
            "iteration": self.iteration,
            "tool": tool,
            "args": args,
            "success": success,
            "duration_ms": int(duration * 1000),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        if not success:
            self.failures += 1
            self.consecutive_failures += 1
        else:
            self.consecutive_failures = 0

    def should_abort(self) -> tuple[bool, str]:
        """Check if agent should abort due to critical failures."""
        if self.iteration >= self.max_iterations:
            return (True, f"Max iterations ({self.max_iterations}) reached")
        if self.consecutive_failures >= 3:
            return (True, f"3 consecutive failures — aborting")
        elapsed = time.time() - self.start_time
        if elapsed > 1800:  # 30 min total
            return (True, f"Time limit exceeded ({int(elapsed)}s)")
        return (False, "")

    def get_summary(self) -> dict:
        return {
            "iterations": self.iteration,
            "tool_calls": len(self.tool_calls),
            "successful_calls": sum(1 for t in self.tool_calls if t["success"]),
            "failed_calls": self.failures,
            "findings": len(self.findings),
            "elapsed_seconds": int(time.time() - self.start_time),
        }


class SelfCorrectingLoop:
    """
    ReAct agent loop with self-correction.

    Architecture:
    1. LLM receives task + system prompt
    2. LLM decides next tool call (Reasoning + Action)
    3. Tool executes → result returned as Observation
    4. LLM evaluates result → decides next step
    5. On failure: LLM diagnoses and retries with different approach
    """

    def __init__(self, mcp_client: Any, system_prompt: str):
        self.client = mcp_client
        self.system_prompt = system_prompt
        self.state = AgentState()

    async def run(self, task: str, evidence_path: str) -> dict:
        """Execute a DFIR analysis task with self-correction."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Task: {task}\nEvidence: {evidence_path}"},
        ]

        while True:
            # Check abort conditions
            should_abort, reason = self.state.should_abort()
            if should_abort:
                logger.warning(f"Agent aborting: {reason}")
                return self._build_result(messages, aborted=True, reason=reason)

            # Step 1: LLM decides next action
            self.state.iteration += 1
            logger.info(f"Iteration {self.state.iteration}")

            try:
                response = await self.client.get_response(messages, self.system_prompt)
            except Exception as e:
                logger.error(f"LLM call failed: {e}")
                self.state.errors.append(str(e))
                continue

            # Check for final answer
            if not response.get("tool_calls"):
                logger.info("Agent produced final answer")
                return self._build_result(messages, aborted=False)

            # Step 2: Execute tool calls
            for tool_call in response["tool_calls"]:
                tool_name = tool_call["name"]
                tool_args = tool_call["arguments"]

                logger.info(f"Calling tool: {tool_name}({tool_args})")

                start = time.time()
                try:
                    result = await self.client.call_tool(tool_name, tool_args)
                    duration = time.time() - start
                    self.state.record_tool_call(tool_name, tool_args, result, True, duration)

                    # Check for large output — truncate if needed
                    result_text = result.get("content", "")
                    if len(result_text) > 100_000:
                        result_text = result_text[:100_000] + \
                            f"\n[TRUNCATED: {len(result_text)} total chars]"

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": result_text,
                    })

                except Exception as e:
                    duration = time.time() - start
                    self.state.record_tool_call(tool_name, tool_args, str(e), False, duration)
                    logger.warning(f"Tool {tool_name} failed: {e}")

                    # Self-correction: provide error context for LLM to recover
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "content": json.dumps({
                            "error": str(e),
                            "tool": tool_name,
                            "suggestions": self._get_recovery_suggestions(tool_name, str(e)),
                        }),
                    })

    def _get_recovery_suggestions(self, tool: str, error: str) -> list:
        """Generate recovery suggestions based on tool and error."""
        suggestions = {
            "fs_list_files": [
                "Check that the image path exists and is accessible",
                "Try scanning partitions first with fs_partition_scan",
                "Specify a partition offset with the offset parameter",
            ],
            "mem_analyze": [
                "Verify the memory capture is a valid format",
                "Try a different Volatility plugin",
                "Check memory_path exists",
            ],
            "timeline_build": [
                "Ensure the source is a disk image or directory",
                "Try on a smaller subset first",
                "Increase timeout for large images",
            ],
        }
        return suggestions.get(tool, [
            "Check that the evidence path exists and is readable",
            "Try a different tool or approach",
            "Examine the error message for specific details",
        ])

    def _build_result(self, messages: list, aborted: bool = False,
                      reason: str = "") -> dict:
        """Build final result from conversation."""
        return {
            "success": not aborted,
            "aborted": aborted,
            "reason": reason if aborted else None,
            "summary": self.state.get_summary(),
            "tool_calls": self.state.tool_calls,
            "findings": self.state.findings,
            "errors": self.state.errors,
            "conversation_length": len(messages),
        }
```

### 3.6 System Prompt — `src/agent/prompts.py`

```python
"""
DFIR Agent System Prompts
Designed to make the agent think like a senior forensic analyst.
"""

DFIR_ANALYST_PROMPT = """You are a Senior DFIR (Digital Forensics & Incident Response) Analyst with 15 years of experience. You have analyzed thousands of compromised systems and can reconstruct attacker activity from forensic artifacts.

## YOUR ROLE
You are examining digital evidence to determine what happened, when, and by whom. Your analysis is methodical, evidence-based, and clearly communicated.

## CORE PRINCIPLES

1. **EVIDENCE INTEGRITY**: Never modify original evidence. All analysis is read-only. If you need to extract files, save them to the results directory.

2. **METHODICAL APPROACH**: Start broad, then go deep. First understand the evidence structure, build a timeline, then investigate specific artifacts.

3. **SELF-CORRECTION**: If a tool returns an error, check the error message carefully and try an alternative approach. Do not report failure until you've tried 3 different approaches.

4. **HALLUCINATION PREVENTION**: 
   - Clearly distinguish between what you observed in tool output vs what you infer
   - If you're unsure about a finding, flag it as "UNVERIFIED" or "INFERRED"
   - Never fabricate tool output or results
   - If output is empty, say so — don't make up findings

5. **CONTEXT MANAGEMENT**:
   - If tool output is very large, summarize key points
   - Focus on the most relevant artifacts for the task
   - Filter timelines to relevant date ranges
   - Prioritize evidence quality over quantity

## STANDARD WORKFLOW

1. **INITIAL TRIAGE**: Run fs_partition_scan → fs_list_files → verify_hash to understand the evidence
2. **TIMELINE BUILDING**: Use timeline_build to create a baseline timeline
3. **ARTIFACT EXTRACTION**: Use carve_files and extract_features for quick wins
4. **DEEP ANALYSIS**: Use mem_analyze, reg_query, scan_yara for targeted investigation
5. **CROSS-REFERENCE**: Compare findings across tools to validate
6. **REPORTING**: Summarize findings with confidence levels

## TOOL USAGE GUIDELINES

- fs_partition_scan: Start here for disk images — understand the layout first
- fs_list_files: List files in directories of interest (Users/, Windows/System32/, etc.)
- fs_extract_file: Extract specific files for detailed analysis
- mem_analyze: Use with windows.pslist.PsList first, then windows.netscan, windows.cmdline
- timeline_build: Build comprehensive timeline, then timeline_filter to narrow down
- carve_files: Look for deleted files of interest
- extract_features: Quick scan for emails, URLs, IPs, credentials
- scan_yara: Scan for known malware signatures
- verify_hash: Verify evidence integrity at start and end

## REPORTING FORMAT

When you have a final answer, structure it as:

```
## INVESTIGATION SUMMARY

**Evidence**: [path]
**Task**: [original task]

### Key Findings
1. [Finding] — [CONFIRMED/INFERRED/UNVERIFIED]
   Source: [tool_name] with [parameters]
   Evidence: [specific tool output]

### Timeline of Key Events
| Timestamp | Event | Artifact | Confidence |
|-----------|-------|----------|------------|

### Artifacts of Interest
- [Artifact]: [significance]

### Open Questions / Gaps
- [What wasn't determined]
```

Remember: Accuracy matters more than speed. It's better to correctly identify 3 artifacts than to hallucinate 20.
"""
```

### 3.7 Project Config — `pyproject.toml`

```toml
[project]
name = "findevil-agent"
version = "1.0.0"
description = "Autonomous DFIR analysis agent for Find Evil! Hackathon"
requires-python = ">=3.10"
license = "MIT"
authors = [
    {name = "Find Evil Team", email = "team@example.com"},
]

dependencies = [
    "fastmcp>=0.1.0",
    "pydantic>=2.0",
    "httpx>=0.27.0",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-asyncio>=0.23.0",
    "black>=24.0",
    "ruff>=0.1.0",
    "mypy>=1.7.0",
]

[project.scripts]
findevil-server = "src.server:main"
findevil-agent = "src.agent.cli:main"

[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"
```

---

## 4. DEPLOYMENT

### 4.1 Setup Script — `scripts/setup.sh`

```bash
#!/bin/bash
set -euo pipefail

echo "=== Find Evil! Agent Setup ==="

# 1. Check for SIFT Workstation
if [ ! -f /usr/bin/fls ]; then
    echo "[!] SIFT tools not found. Installing..."
    curl -L https://raw.githubusercontent.com/teamdfir/sift-saltstack/master/bootstrap.sh | sudo bash
fi

# 2. Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install -e .

# 3. Create evidence directories
echo "[*] Creating evidence directories..."
mkdir -p /evidence/{disk,memory,network,cases}
mkdir -p /results/{audit,carved,timelines}

# 4. Verify tools
echo "[*] Verifying tools..."
for tool in fls icat mmls fsstat foremost bulk_extractor tshark yara hashdeep; do
    if command -v $tool &>/dev/null; then
        echo "  [+] $tool found at $(which $tool)"
    else
        echo "  [-] $tool NOT found"
    fi
done

echo "=== Setup Complete ==="
echo "Run: python -m src.server"
echo "Then connect Claude Code or any MCP client"
```

---

## 5. TESTING

### 5.1 Tool Tests — `tests/test_tools.py`

```python
"""MCP tool integration tests."""
import json
from src.tools import filesystem

def test_list_files():
    """Test that fs_list_files returns valid file listing."""
    result = filesystem.list_files("/dev/null")
    # Should fail gracefully
    assert result.success == False
    assert result.error is not None

def test_scan_partitions():
    """Test partition scanning."""
    import tempfile
    # Create a minimal test image
    with tempfile.NamedTemporaryFile(suffix=".raw") as f:
        f.write(b"\x00" * 1024 * 1024)  # 1MB zeroed
        f.flush()
        result = filesystem.scan_partitions(f.name)
        # Image is empty — should return no partitions (not crash)
        assert result.success == True
```

### 5.2 Security Tests — `tests/test_security.py`

```python
"""Evidence integrity tests."""
from pathlib import Path
import pytest
from src.security import EvidenceGuard, EvidenceIntegrityError

def test_path_validation():
    guard = EvidenceGuard(Path("/evidence"))
    # Should pass
    guard.assert_safe_path("/evidence/disk/image.raw")
    # Should fail
    with pytest.raises(EvidenceIntegrityError):
        guard.assert_safe_path("/etc/passwd")

def test_write_restriction():
    guard = EvidenceGuard(Path("/evidence"))
    # Should fail — can't write to evidence dir
    with pytest.raises(EvidenceIntegrityError):
        guard.assert_write_safe("/evidence/disk/image.raw")
    # Should pass — can write to results
    guard.assert_write_safe("/evidence/results/analysis.txt")
```

---

*Architecture v1.0 — Generated by God Syndicate Arsenal ORCHESTRATOR*
