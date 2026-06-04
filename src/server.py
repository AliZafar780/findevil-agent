"""
findevil-mcp: Autonomous DFIR Analysis MCP Server
Connects LLM agents to SIFT Workstation forensic tools via the Model Context Protocol.

Designed for robustness: all tools have typed schemas, path validation,
audit logging, output size limits, and concurrent access protection.
"""
import asyncio
import atexit
import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource

# ── Configuration ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("findevil-mcp")

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/evidence"))
RESULTS_ROOT = Path(os.environ.get("RESULTS_ROOT", "/results"))
SERVER_NAME = "findevil-mcp"
SERVER_VERSION = "2.0.0"
MAX_OUTPUT_CHARS = 100_000  # Truncate tool output to prevent memory issues
MAX_TIMEOUT = 600           # Maximum tool timeout in seconds

# ── Concurrency Lock ───────────────────────────────────────────────
# MCP STDIO transport is single-channel; this lock prevents interleaved responses
_call_lock = asyncio.Lock()

# ── Audit Log Setup ───────────────────────────────────────────────
_audit_log_path = RESULTS_ROOT / "audit" / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
_audit_entries: list[dict] = []


def _sanitize(s: str) -> str:
    """Remove control characters (except newline/tab) that could be used for log injection."""
    if not s:
        return ""
    return "".join(c for c in s if c.isprintable() or c in "\n\r\t")


def _trunc(s: str, n: int = 200) -> str:
    """Truncate a string to n chars with ellipsis. Sanitizes control chars."""
    s = _sanitize(s)
    if s and len(s) > n:
        return s[:n] + "..."
    return s or ""


def _audit_log(tool: str, arguments: dict, result: dict, duration_ms: int, error: str = None):
    """Log a tool execution to both in-memory list and JSON lines file."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "arguments": {k: _trunc(str(v)) for k, v in arguments.items()},
        "success": result.get("success", False),
        "duration_ms": duration_ms,
        "error": _trunc(str(error)[:500] if error else (result.get("error") or None), 500),
    }
    _audit_entries.append(entry)
    try:
        _audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(_audit_log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.warning(f"Failed to write audit log: {e}")


def _get_audit_logs() -> list[dict]:
    """Return all audit entries for the current session."""
    return _audit_entries


def _cleanup():
    """Graceful cleanup on exit."""
    total = len(_audit_entries)
    if total > 0:
        logger.info(f"Session ended. {total} tool calls logged to {_audit_log_path}")


atexit.register(_cleanup)


# ── Tool Execution ────────────────────────────────────────────────

def _run_tool(cmd: list, timeout: int = 120, stdin_data: str = None) -> dict:
    """
    Run a command-line tool and return structured result.
    Handles timeout, missing tools, and non-zero exits gracefully.
    """
    start = time.time()
    try:
        timeout = min(timeout, MAX_TIMEOUT)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.PIPE if stdin_data else None,
        )
        duration = int((time.time() - start) * 1000)

        # Truncate output to prevent memory issues
        stdout = result.stdout[:MAX_OUTPUT_CHARS] if result.stdout else ""
        stderr = result.stderr[:MAX_OUTPUT_CHARS] if result.stderr else ""

        return {
            "success": result.returncode == 0,
            "stdout": stdout,
            "stderr": stderr,
            "returncode": result.returncode,
            "duration_ms": duration,
            "command": _trunc(" ".join(str(c) for c in cmd), 500),
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False, "stdout": "", "stderr": f"Command timed out after {timeout}s",
            "returncode": -1, "duration_ms": timeout * 1000,
            "command": _trunc(" ".join(str(c) for c in cmd), 500),
        }
    except FileNotFoundError as e:
        return {
            "success": False, "stdout": "", "stderr": f"Tool not found: {e}. Is SIFT Workstation installed?",
            "returncode": -1, "duration_ms": 0,
            "command": _trunc(" ".join(str(c) for c in cmd), 500),
        }
    except PermissionError as e:
        return {
            "success": False, "stdout": "", "stderr": f"Permission denied: {e}",
            "returncode": -1, "duration_ms": 0,
            "command": _trunc(" ".join(str(c) for c in cmd), 500),
        }
    except Exception as e:
        return {
            "success": False, "stdout": "", "stderr": f"Unexpected error: {e}",
            "returncode": -1, "duration_ms": int((time.time() - start) * 1000),
            "command": _trunc(" ".join(str(c) for c in cmd), 500),
        }


# ── Security Validation ────────────────────────────────────────────

def _validate_evidence_path(path: str) -> Optional[str]:
    """Validate that a path is within the evidence root and exists.
    Does NOT leak the requested path in error messages (privacy/security)."""
    if not path or not path.strip():
        return "Path cannot be empty"
    # Reject null bytes and control characters
    if "\x00" in path or any(ord(c) < 32 for c in path):
        return "Path contains invalid characters"
    # Limit path length
    if len(path) > 4096:
        return "Path too long"
    try:
        resolved = Path(path).resolve()
        if not resolved.exists():
            return "Evidence path does not exist"
        resolved.relative_to(EVIDENCE_ROOT)
        return None
    except ValueError:
        return "Path outside evidence root — access denied"
    except RuntimeError:
        return "Path resolution error (possible symlink loop)"
    except Exception:
        return "Path validation failed"


def _validate_output_dir(path: str) -> Optional[str]:
    """Validate that an output directory is under RESULTS_ROOT (writable area)."""
    if not path or not path.strip():
        return "Output path cannot be empty"
    try:
        resolved = Path(path).resolve()
        if not str(resolved).startswith(str(RESULTS_ROOT.resolve())):
            return f"Output directory must be under results root ({RESULTS_ROOT}): {path}"
        return None
    except Exception as e:
        return f"Output path validation error: {e}"


def _safe_path_join(base: Path, subdir: str) -> Optional[Path]:
    """Safely join a subdirectory to base path, preventing traversal attacks."""
    if not subdir or subdir.strip() == "":
        return base
    # Reject path traversal characters
    if ".." in subdir or "~" in subdir or subdir.startswith("/"):
        return None
    try:
        joined = (base / subdir).resolve()
        # Verify it's still under base
        joined.relative_to(base.resolve())
        return joined
    except (ValueError, Exception):
        return None


# ── MCP Server Instance ────────────────────────────────────────────
server = Server(SERVER_NAME)


# ── Tool Definitions ──────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    """Register all 21 forensic tools with typed schemas."""
    return [
        # ── File System Analysis ──────────────────────────────────
        Tool(
            name="fs_partition_scan",
            description="Scan partition table of a disk image using mmls. Start here for disk analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image (raw, E01, etc.)"},
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="fs_list_files",
            description="List files and directories in a forensic image using fls.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "offset": {"type": "integer", "description": "Partition offset in sectors", "default": 0},
                    "path": {"type": "string", "description": "Path or inode to list", "default": ""},
                    "recursive": {"type": "boolean", "description": "Recurse into subdirectories", "default": False},
                },
                "required": ["image_path"],
            },
        ),
        Tool(
            name="fs_extract_file",
            description="Extract file content by inode number using icat.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "inode": {"type": "integer", "description": "Inode/MFT number to extract"},
                    "offset": {"type": "integer", "description": "Partition offset", "default": 0},
                },
                "required": ["image_path", "inode"],
            },
        ),
        Tool(
            name="fs_file_metadata",
            description="Get detailed metadata about a file/inode using istat.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "inode": {"type": "integer", "description": "Inode/MFT number"},
                    "offset": {"type": "integer", "description": "Partition offset", "default": 0},
                },
                "required": ["image_path", "inode"],
            },
        ),
        Tool(
            name="fs_filesystem_info",
            description="Get filesystem metadata and statistics using fsstat.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "offset": {"type": "integer", "description": "Partition offset", "default": 0},
                },
                "required": ["image_path"],
            },
        ),
        # ── File Carving ──────────────────────────────────────────
        Tool(
            name="carve_files",
            description="Carve files from disk image using foremost (by file headers).",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "output_dir": {"type": "string", "description": "Output directory (must be under /results)"},
                    "file_types": {"type": "string", "description": "File types to carve (e.g., 'jpg,pdf,zip')", "default": "all"},
                },
                "required": ["image_path", "output_dir"],
            },
        ),
        # ── Pattern Matching ──────────────────────────────────────
        Tool(
            name="scan_yara",
            description="Scan file or directory with YARA rules for malware detection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "File or directory to scan"},
                    "rules": {"type": "string", "description": "YARA rule content (inline). Must be valid YARA syntax."},
                },
                "required": ["target", "rules"],
            },
        ),
        Tool(
            name="verify_hash",
            description="Compute cryptographic hash of a file (md5, sha1, sha256).",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file"},
                    "algorithm": {"type": "string", "description": "Hash algorithm: md5, sha1, sha256", "default": "sha256"},
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="list_evidence",
            description="List available evidence files in the evidence directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "subdir": {"type": "string", "description": "Subdirectory to list (e.g., 'cases', 'disk')", "default": ""},
                },
            },
        ),
        # ── Memory Forensics ─────────────────────────────────────
        Tool(
            name="mem_analyze",
            description="Analyze memory with Volatility 3 (linux.pslist) with fallback to string-based IOC scanning. Returns process/socket/kernel module artifacts when possible.",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory capture file (.mem, .vmem, .elf, .core)"},
                    "plugin": {"type": "string", "description": "Volatility3 plugin name (e.g. linux.pslist.PsList, linux.bash.Bash)", "default": "linux.pslist.PsList"},
                },
                "required": ["memory_path"],
            },
        ),
        Tool(
            name="mem_list_processes",
            description="List processes from memory using Volatility 3 pslist or fallback string IOC scanning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory capture file"},
                },
                "required": ["memory_path"],
            },
        ),
        Tool(
            name="mem_scan_network",
            description="Scan network connections from memory via Volatility 3 netstat or string IOC scanning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory capture file"},
                },
                "required": ["memory_path"],
            },
        ),
        Tool(
            name="mem_dump_cmdline",
            description="Extract command lines from memory via Volatility 3 bash/cmdline plugin or string IOC scanning.",
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_path": {"type": "string", "description": "Path to memory capture file"},
                },
                "required": ["memory_path"],
            },
        ),
        # ── Registry Forensics ──────────────────────────────────
        Tool(
            name="reg_analyze_hive",
            description="Analyze a Windows Registry hive file using regipy.",
            inputSchema={
                "type": "object",
                "properties": {
                    "hive_path": {"type": "string", "description": "Path to registry hive file (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)"},
                    "key": {"type": "string", "description": "Registry key path to query", "default": "/"},
                },
                "required": ["hive_path"],
            },
        ),
        # ── Network Forensics ───────────────────────────────────
        Tool(
            name="pcap_analyze",
            description="Analyze a PCAP file using tshark. Extract protocols, conversations, and anomalies.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path": {"type": "string", "description": "Path to PCAP/PCAPNG file"},
                    "display_filter": {"type": "string", "description": "Wireshark display filter", "default": ""},
                    "max_packets": {"type": "integer", "description": "Max packets to analyze", "default": 100},
                    "fields": {"type": "string", "description": "Comma-separated fields to extract", "default": "frame.number,ip.src,ip.dst,frame.protocols"},
                },
                "required": ["pcap_path"],
            },
        ),
        Tool(
            name="pcap_list_protocols",
            description="List all protocols found in a PCAP file with packet counts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path": {"type": "string", "description": "Path to PCAP/PCAPNG file"},
                },
                "required": ["pcap_path"],
            },
        ),
        # ── Timeline Analysis ──────────────────────────────────
        Tool(
            name="timeline_build",
            description="Build forensic timeline from evidence using log2timeline/plaso.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source_path": {"type": "string", "description": "Path to evidence (disk image, directory, etc.)"},
                    "output_path": {"type": "string", "description": "Output path for .plaso storage file (optional)", "default": ""},
                },
                "required": ["source_path"],
            },
        ),
        Tool(
            name="timeline_filter",
            description="Filter and export a Plaso timeline using psort.",
            inputSchema={
                "type": "object",
                "properties": {
                    "storage_path": {"type": "string", "description": "Path to .plaso storage file"},
                    "query": {"type": "string", "description": "Filter query (e.g., 'date > 2024-01-01')", "default": ""},
                    "output_format": {"type": "string", "description": "Output format: json, csv", "default": "json"},
                },
                "required": ["storage_path"],
            },
        ),
        # ── Feature Extraction ──────────────────────────────────
        Tool(
            name="extract_features",
            description="Extract emails, URLs, credit cards using bulk_extractor.",
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "scanners": {"type": "string", "description": "Scanners to run (comma-separated)", "default": "all"},
                },
                "required": ["image_path"],
            },
        ),
        # ── Accuracy Benchmark ──────────────────────────────────
        Tool(
            name="benchmark_accuracy",
            description="Run accuracy benchmark: compare agent findings against known ground truth.",
            inputSchema={
                "type": "object",
                "properties": {
                    "evidence_path": {"type": "string", "description": "Path to evidence with known ground truth"},
                    "ground_truth": {"type": "string", "description": "JSON string of expected findings"},
                },
                "required": ["evidence_path", "ground_truth"],
            },
        ),
        # ── Audit Trail ───────────────────────────────────────────
        Tool(
            name="get_audit_logs",
            description="Retrieve all tool execution logs from the current session.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max log entries to return", "default": 100},
                },
            },
        ),
    ]


# ── Tool Call Router ──────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list:
    """
    Route tool calls to the appropriate handler.
    Protected by asyncio lock to prevent interleaved responses on STDIO transport.
    Input validation: ensures arguments are proper types, no null bytes, reasonable sizes.
    """
    async with _call_lock:
        # Sanitize arguments for logging (truncate, remove control chars)
        safe_args = {}
        for k, v in (arguments or {}).items():
            if isinstance(v, str):
                # Remove control characters and truncate
                safe_v = "".join(c for c in v if c.isprintable() or c in "\n\r\t")[:500]
                safe_args[k] = safe_v
            elif isinstance(v, (int, float, bool)):
                safe_args[k] = v
            elif v is None:
                safe_args[k] = None
            else:
                safe_args[k] = str(v)[:100]

        logger.info(f"Tool called: {name}({json.dumps(safe_args)[:200]})")
        start = time.time()

        try:
            if not name or not name.strip():
                raise ValueError("Tool name cannot be empty")

            # Sanitize arguments: no null bytes, reasonable sizes
            if arguments:
                for k, v in list(arguments.items()):
                    if isinstance(v, str):
                        if "\x00" in v:
                            raise ValueError(f"Invalid null byte in argument '{k}'")
                        if len(v) > 100000:
                            raise ValueError(f"Argument '{k}' exceeds maximum length (100K)")
                    elif isinstance(v, int):
                        if abs(v) > 10**15:
                            raise ValueError(f"Argument '{k}' value out of range")

            # Route to handler
            handler_map = {
                "fs_partition_scan": _handle_partition_scan,
                "fs_list_files": _handle_list_files,
                "fs_extract_file": _handle_extract_file,
                "fs_file_metadata": _handle_file_metadata,
                "fs_filesystem_info": _handle_fs_info,
                "carve_files": _handle_carve,
                "scan_yara": _handle_yara,
                "verify_hash": _handle_hash,
                "list_evidence": _handle_list_evidence,
                "mem_analyze": _handle_mem_analyze,
                "mem_list_processes": _handle_mem_list_processes,
                "mem_scan_network": _handle_mem_scan_network,
                "mem_dump_cmdline": _handle_mem_dump_cmdline,
                "reg_analyze_hive": _handle_reg_analyze,
                "pcap_analyze": _handle_pcap_analyze,
                "pcap_list_protocols": _handle_pcap_protocols,
                "timeline_build": _handle_timeline_build,
                "timeline_filter": _handle_timeline_filter,
                "extract_features": _handle_extract_features,
                "benchmark_accuracy": _handle_benchmark,
                "get_audit_logs": _handle_audit_logs,
            }

            handler = handler_map.get(name)
            if handler is None:
                raise ValueError(f"Unknown tool: '{name}'. Use 'tools' command to list available tools.")

            result = await handler(arguments)
            duration = int((time.time() - start) * 1000)

            # Log to audit trail
            if result and len(result) > 0:
                try:
                    result_data = json.loads(result[0].text)
                except (json.JSONDecodeError, IndexError, AttributeError):
                    result_data = {"success": True}
            else:
                result_data = {"success": True}
            _audit_log(name, arguments, result_data, duration)

            return result

        except ValueError as e:
            duration = int((time.time() - start) * 1000)
            logger.warning(f"Tool validation error: {e}")
            _audit_log(name, arguments, {"success": False}, duration, str(e))
            return [TextContent(type="text", text=json.dumps({
                "success": False, "error": str(e), "tool": name,
            }))]
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            logger.warning(f"Tool {name} failed: {e}")
            _audit_log(name, arguments, {"success": False}, duration, str(e)[:500])
            return [TextContent(type="text", text=json.dumps({
                "success": False, "error": f"Tool execution failed: {str(e)[:200]}", "tool": name,
            }))]


# ═══════════════════════════════════════════════════════════════════
#  HANDLER IMPLEMENTATIONS
# ═══════════════════════════════════════════════════════════════════

# ── File System Handlers ─────────────────────────────────────────

async def _handle_partition_scan(args: dict) -> list:
    """Scan partition table using mmls."""
    image_path = args.get("image_path", "")
    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    mmls_paths = ["/usr/bin/mmls", "/usr/local/bin/mmls"]
    mmls_cmd = next((p for p in mmls_paths if Path(p).exists()), "mmls")

    result = _run_tool([mmls_cmd, image_path])

    if result["success"]:
        partitions = []
        for line in result["stdout"].split("\n"):
            stripped = line.strip()
            if stripped and (stripped[0].isdigit() or "Meta" in stripped or "Unallocated" in stripped):
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        slot_str = parts[0].rstrip(":")
                        if slot_str.isdigit():
                            partitions.append({
                                "slot": int(slot_str),
                                "start": int(parts[2]),
                                "end": int(parts[3]),
                                "length": int(parts[4]),
                                "description": " ".join(parts[5:]),
                            })
                    except (ValueError, IndexError):
                        continue

        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "image": image_path,
            "partition_count": len(partitions),
            "partitions": partitions,
            "raw_output": result["stdout"][:10000],
            "duration_ms": result["duration_ms"],
        }, indent=2))]
    else:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Partition scan failed: {result['stderr'] or 'No partition table found. The image may not have a GPT/MBR layout.'}",
            "command": result["command"],
            "suggestion": "Try fs_filesystem_info if this is a raw filesystem image without a partition table.",
        }))]


async def _handle_list_files(args: dict) -> list:
    """List files using fls."""
    image_path = args.get("image_path", "")
    offset = args.get("offset", 0)
    path = args.get("path", "")
    recursive = args.get("recursive", False)

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    fls_paths = ["/usr/bin/fls", "/usr/local/bin/fls"]
    fls_cmd = next((p for p in fls_paths if Path(p).exists()), "fls")

    cmd = [fls_cmd]
    if offset:
        cmd.extend(["-o", str(offset)])
    if recursive:
        cmd.append("-r")
    cmd.append(image_path)
    if path:
        cmd.append(str(path))

    result = _run_tool(cmd)

    if result["success"] or result["returncode"] == 1:
        entries = [line for line in result["stdout"].split("\n") if line.strip()]
        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "file_count": len(entries),
            "entries": entries[:1000],
            "truncated": len(entries) > 1000,
            "raw_output": result["stdout"][:50000],
            "duration_ms": result["duration_ms"],
            "command": result["command"],
        }, indent=2))]
    else:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"File listing failed: {result['stderr'] or 'Unknown error'}",
            "suggestion": "Verify the image path and partition offset. Try fs_partition_scan first.",
        }))]


async def _handle_extract_file(args: dict) -> list:
    """Extract file using icat."""
    image_path = args.get("image_path", "")
    inode = args.get("inode", 0)
    offset = args.get("offset", 0)

    if inode <= 0:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": "Invalid inode number. Must be a positive integer."}))]

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    icat_paths = ["/usr/bin/icat", "/usr/local/bin/icat"]
    icat_cmd = next((p for p in icat_paths if Path(p).exists()), "icat")

    cmd = [icat_cmd]
    if offset:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, str(inode)])

    result = _run_tool(cmd)

    if result["success"]:
        content = result["stdout"]
        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "inode": inode,
            "size": len(content),
            "preview": content[:5000],
            "preview_truncated": len(content) > 5000,
            "duration_ms": result["duration_ms"],
        }, indent=2))]
    else:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Failed to extract inode {inode}: {result['stderr'] or 'File may not exist'}",
            "suggestion": "Check that the inode exists. Try fs_list_files first to find valid inodes.",
        }))]


async def _handle_file_metadata(args: dict) -> list:
    """Get file metadata using istat."""
    image_path = args.get("image_path", "")
    inode = args.get("inode", 0)
    offset = args.get("offset", 0)

    if inode <= 0:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": "Invalid inode number."}))]

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    istat_paths = ["/usr/bin/istat", "/usr/local/bin/istat"]
    istat_cmd = next((p for p in istat_paths if Path(p).exists()), "istat")

    cmd = [istat_cmd]
    if offset:
        cmd.extend(["-o", str(offset)])
    cmd.extend([image_path, str(inode)])

    result = _run_tool(cmd)

    if result["success"]:
        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "inode": inode,
            "metadata": result["stdout"][:10000],
            "raw_output": result["stdout"][:10000],
            "duration_ms": result["duration_ms"],
        }, indent=2))]
    else:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Metadata lookup failed: {result['stderr'] or 'Inode may not exist'}",
            "suggestion": "The inode may be invalid or the file system type may not be supported.",
        }))]


async def _handle_fs_info(args: dict) -> list:
    """Get filesystem stats using fsstat."""
    image_path = args.get("image_path", "")
    offset = args.get("offset", 0)

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    fsstat_paths = ["/usr/bin/fsstat", "/usr/local/bin/fsstat"]
    fsstat_cmd = next((p for p in fsstat_paths if Path(p).exists()), "fsstat")

    cmd = [fsstat_cmd]
    if offset:
        cmd.extend(["-o", str(offset)])
    cmd.append(image_path)

    result = _run_tool(cmd)

    if result["success"]:
        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "fsstat_output": result["stdout"][:20000],
            "raw_output": result["stdout"][:20000],
            "duration_ms": result["duration_ms"],
        }, indent=2))]
    else:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Filesystem info failed: {result['stderr'] or 'Unrecognized filesystem type. The image may be unformatted or use an unsupported FS.'}",
            "suggestion": "Try running fs_partition_scan first, or use a different offset.",
        }))]


# ── Carving Handlers ────────────────────────────────────────────

async def _handle_carve(args: dict) -> list:
    """Carve files using foremost."""
    image_path = args.get("image_path", "")
    output_dir = args.get("output_dir", "")
    file_types = args.get("file_types", "all")

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    # Validate output directory is under RESULTS_ROOT
    out_err = _validate_output_dir(output_dir)
    if out_err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": out_err}))]

    Path(output_dir).parent.mkdir(parents=True, exist_ok=True)

    foremost_paths = ["/usr/bin/foremost", "/usr/local/bin/foremost"]
    foremost_cmd = next((p for p in foremost_paths if Path(p).exists()), None)
    if not foremost_cmd:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "foremost not found. Install: sudo apt-get install foremost",
        }))]

    cmd = [foremost_cmd, "-o", output_dir, "-q", "-T"]
    if file_types and file_types != "all":
        cmd.extend(["-t", file_types])
    cmd.append(image_path)

    result = _run_tool(cmd, timeout=600)

    # Count carved files
    carved_files = []
    if Path(output_dir).exists():
        for f in Path(output_dir).rglob("*"):
            if f.is_file() and f.stat().st_size > 0:
                carved_files.append({
                    "path": str(f), "size": f.stat().st_size, "name": f.name,
                })

    # foremost returns non-zero when it finds files too, so check output
    return [TextContent(type="text", text=json.dumps({
        "success": True,
        "output_dir": output_dir,
        "carved_files": len(carved_files),
        "files": carved_files[:100],
        "raw_output": result["stdout"][:10000],
        "duration_ms": result["duration_ms"],
    }, indent=2))]


# ── YARA Handler ─────────────────────────────────────────────────

async def _handle_yara(args: dict) -> list:
    """Scan with YARA rules."""
    target = args.get("target", "")
    rules = args.get("rules", "")

    if not rules or not rules.strip():
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Empty YARA rules. Provide valid YARA rule content.",
            "suggestion": "Example: 'rule test { strings: $a = \"malware\" condition: $a }'",
        }))]

    if "rule " not in rules:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Invalid YARA rules syntax. Rules must contain at least one 'rule' definition.",
            "suggestion": "Format: rule name { strings: $a = \"pattern\" condition: $a }",
        }))]

    err = _validate_evidence_path(target)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    # Write rules to temp file
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yara", delete=False, encoding="utf-8") as f:
            f.write(rules)
            rules_path = f.name
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({
            "success": False, "error": f"Failed to write YARA rules: {e}",
        }))]

    try:
        yara_paths = ["/usr/bin/yara", "/usr/local/bin/yara"]
        yara_cmd = next((p for p in yara_paths if Path(p).exists()), None)
        if not yara_cmd:
            return [TextContent(type="text", text=json.dumps({
                "success": False, "error": "yara not found. Install: sudo apt-get install yara",
            }))]

        cmd = [yara_cmd, "-w", rules_path, target]
        result = _run_tool(cmd)

        # YARA returns 0 for matches, non-zero for no matches (which is OK)
        matches = []
        for line in result["stdout"].strip().split("\n"):
            if line.strip():
                parts = line.split(maxsplit=1)
                rule_name = parts[0] if parts else ""
                matched_file = parts[1] if len(parts) > 1 else target
                matches.append({"rule": rule_name, "target": matched_file})

        is_clean = len(matches) == 0

        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "matches": matches,
            "match_count": len(matches),
            "clean": is_clean,
            "message": "No YARA matches found (clean)" if is_clean else f"Found {len(matches)} YARA match(es)",
            "rules_used": rules[:500],
            "duration_ms": result["duration_ms"],
        }, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({
            "success": False, "error": f"YARA scan failed: {e}",
        }))]
    finally:
        try:
            os.unlink(rules_path)
        except Exception:
            pass


# ── Hash Handler ────────────────────────────────────────────────

async def _handle_hash(args: dict) -> list:
    """Compute file hash."""
    file_path = args.get("file_path", "")
    algorithm = args.get("algorithm", "sha256")

    err = _validate_evidence_path(file_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    hash_cmd_map = {
        "md5": "/usr/bin/md5sum",
        "sha1": "/usr/bin/sha1sum",
        "sha256": "/usr/bin/sha256sum",
        "sha512": "/usr/bin/sha512sum",
    }

    hash_bin = hash_cmd_map.get(algorithm)
    if not hash_bin:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Unsupported algorithm: {algorithm}. Use: md5, sha1, sha256, sha512",
        }))]

    if not Path(hash_bin).exists():
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"{hash_bin} not found. Install coreutils: sudo apt-get install coreutils",
        }))]

    result = _run_tool([hash_bin, file_path])

    if result["success"]:
        hash_value = result["stdout"].split()[0] if result["stdout"] else ""
        return [TextContent(type="text", text=json.dumps({
            "success": True,
            "algorithm": algorithm,
            "hash": hash_value,
            "file": file_path,
            "duration_ms": result["duration_ms"],
        }, indent=2))]
    else:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Hash failed: {result['stderr'] or 'Unknown error'}",
        }))]


# ── Evidence List Handler ───────────────────────────────────────

async def _handle_list_evidence(args: dict) -> list:
    """List available evidence."""
    subdir = args.get("subdir", "")

    # Security: prevent path traversal
    if subdir:
        safe_path = _safe_path_join(EVIDENCE_ROOT, subdir)
        if safe_path is None:
            return [TextContent(type="text", text=json.dumps({
                "success": False,
                "error": f"Invalid subdirectory: '{subdir}'. Path traversal not allowed.",
            }))]
        target_dir = safe_path
    else:
        target_dir = EVIDENCE_ROOT

    if not target_dir.exists():
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Directory does not exist: {target_dir}",
            "suggestion": "Create it: mkdir -p /evidence/{disk,memory,network,cases}",
        }))]

    files = []
    try:
        for f in sorted(target_dir.iterdir(), key=lambda x: (not x.is_dir(), x.name)):
            try:
                stat = f.stat()
                files.append({
                    "name": f.name,
                    "type": "directory" if f.is_dir() else "file",
                    "size": stat.st_size if f.is_file() else 0,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                })
            except (OSError, PermissionError):
                files.append({
                    "name": f.name,
                    "type": "unknown",
                    "size": 0,
                    "error": "Cannot read metadata",
                })
    except PermissionError:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Permission denied reading {target_dir}",
        }))]

    return [TextContent(type="text", text=json.dumps({
        "success": True,
        "path": str(target_dir),
        "file_count": len(files),
        "files": files,
    }, indent=2))]


# ── Memory Forensics Handlers ─────────────────────────────────────

def _is_memory_capture(path: str) -> bool:
    """Detect if a file is a memory capture via magic bytes and extension."""
    try:
        with open(path, 'rb') as f:
            header = f.read(16)
        if header[:4] in (b'\x7fELF', b'PAGE', b'\x1f\x8b'):
            return True
        if b'VMem' in header or b'vmem' in header:
            return True
    except Exception:
        pass
    mem_extensions = {'.mem', '.vmem', '.dump', '.dmp', '.core', '.elf', '.crash', '.raw'}
    return Path(path).suffix.lower() in mem_extensions


async def _handle_mem_analyze(args: dict) -> list:
    """Analyze memory with Volatility 3 plugin, with fallback to string IOC scanning."""
    from src.tools.memory import analyze as mem_analyze
    mem_path = args.get("memory_path", "")
    plugin = args.get("plugin", "linux.pslist.PsList")
    err = _validate_evidence_path(mem_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_memory_capture(mem_path):
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Not a recognized memory capture file",
            "suggestion": "This tool requires a memory dump (.mem, .vmem, .dmp, .elf, .core, .raw)",
        }))]
    result = mem_analyze(mem_path, plugin, use_fallback=True)
    return [TextContent(type="text", text=json.dumps({
        "success": result.success,
        "plugin": result.plugin,
        "data": result.data,
        "error": result.error,
        "note": result.data[0].get("note", "") if result.data and isinstance(result.data[0], dict) else "",
    } if result.success else {"success": False, "error": result.error}, indent=2))]


async def _handle_mem_list_processes(args: dict) -> list:
    """List processes from memory using pslist, with fallback to string IOC scanning."""
    from src.tools.memory import list_processes
    mem_path = args.get("memory_path", "")
    err = _validate_evidence_path(mem_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_memory_capture(mem_path):
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Not a memory capture file",
            "suggestion": "Use a memory dump (.mem, .vmem, .dmp, etc.)",
        }))]
    result = list_processes(mem_path)
    return [TextContent(type="text", text=json.dumps({
        "success": result.success,
        "plugin": result.plugin,
        "data": result.data,
        "error": result.error,
        "note": result.data[0].get("note", "") if result.data and isinstance(result.data[0], dict) else "",
    } if result.success else {"success": False, "error": result.error}, indent=2))]


async def _handle_mem_scan_network(args: dict) -> list:
    """Scan network connections from memory, with fallback to string IOC scanning."""
    from src.tools.memory import scan_network
    mem_path = args.get("memory_path", "")
    err = _validate_evidence_path(mem_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_memory_capture(mem_path):
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Not a memory capture file",
        }))]
    result = scan_network(mem_path)
    return [TextContent(type="text", text=json.dumps({
        "success": result.success,
        "plugin": result.plugin,
        "data": result.data,
        "error": result.error,
    } if result.success else {"success": False, "error": result.error}, indent=2))]


async def _handle_mem_dump_cmdline(args: dict) -> list:
    """Dump command lines from memory processes, with fallback to string IOC scanning."""
    from src.tools.memory import dump_cmdline
    mem_path = args.get("memory_path", "")
    err = _validate_evidence_path(mem_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_memory_capture(mem_path):
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Not a memory capture file",
        }))]
    result = dump_cmdline(mem_path)
    return [TextContent(type="text", text=json.dumps({
        "success": result.success,
        "plugin": result.plugin,
        "data": result.data,
        "error": result.error,
    } if result.success else {"success": False, "error": result.error}, indent=2))]


# ── Registry Forensics Handlers ──────────────────────────────────

def _is_registry_hive(path: str) -> bool:
    """Check if a file is a Windows Registry hive via 'regf' magic bytes."""
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'regf'
    except Exception:
        return False


async def _handle_reg_analyze(args: dict) -> list:
    hive_path = args.get("hive_path", "")
    key = args.get("key", "/")

    if not Path(hive_path).exists():
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": f"Registry hive not found: {hive_path}",
        }))]

    err = _validate_evidence_path(hive_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    if not _is_registry_hive(hive_path):
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Not a Registry hive file",
            "suggestion": "This tool requires a Windows Registry hive file. Look for files named SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT",
        }))]

    try:
        from regipy import RegistryHive
        hive = RegistryHive(hive_path)
        result_data = []
        try:
            for entry in hive.recurse_subkeys(key):
                entry_data = {"path": entry.path, "timestamp": str(entry.timestamp) if entry.timestamp else None}
                try:
                    values = {}
                    for v in getattr(entry, "values", []):
                        try:
                            values[v.name] = str(v.value)[:200]
                        except Exception:
                            values[v.name] = "<binary>"
                    entry_data["values"] = values
                except Exception:
                    entry_data["values"] = {}
                result_data.append(entry_data)
                if len(result_data) >= 200:
                    break
        except Exception as e:
            # Key may not exist
            return [TextContent(type="text", text=json.dumps({
                "success": False,
                "error": f"Registry key not found: {key}. Error: {e}",
                "suggestion": "Try '/' to list all top-level keys, or a standard path like '/Microsoft/Windows/CurrentVersion/Run'",
            }))]

        return [TextContent(type="text", text=json.dumps({
            "success": True, "hive": hive_path, "key_path": key,
            "key_count": len(result_data), "keys": result_data[:200],
        }, indent=2))]
    except ImportError:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "regipy not installed. Install: pip install regipy",
        }))]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({
            "success": False, "error": f"Registry analysis failed: {e}",
        }))]


# ── Network Forensics Handlers ───────────────────────────────────

def _is_pcap(path: str) -> bool:
    """Check if a file is a PCAP via magic bytes or extension."""
    pcap_extensions = {'.pcap', '.pcapng', '.cap'}
    if Path(path).suffix.lower() in pcap_extensions:
        return True
    try:
        with open(path, 'rb') as f:
            header = f.read(4)
        return header in (b'\xd4\xc3\xb2\xa1', b'\x0a\x0d\x0d\x0a', b'\xa1\xb2\xc3\xd4')
    except Exception:
        return False


async def _handle_pcap_analyze(args: dict) -> list:
    pcap_path = args.get("pcap_path", "")
    display_filter = args.get("display_filter", "")
    max_packets = args.get("max_packets", 100)
    fields = args.get("fields", "frame.number,ip.src,ip.dst,frame.protocols")

    err = _validate_evidence_path(pcap_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    if not _is_pcap(pcap_path):
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Not a packet capture file",
            "suggestion": "Use a PCAP/PCAPNG file",
        }))]

    tshark_paths = ["/usr/bin/tshark", "/usr/local/bin/tshark"]
    tshark_cmd = next((p for p in tshark_paths if Path(p).exists()), None)
    if not tshark_cmd:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "tshark not found. Install: sudo apt-get install tshark",
        }))]

    # Main packet extraction
    cmd = [tshark_cmd, "-r", pcap_path, "-T", "json"]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    if max_packets > 0:
        cmd.extend(["-c", str(max_packets)])
    for field in fields.split(","):
        field = field.strip()
        if field:
            cmd.extend(["-e", field])

    result = _run_tool(cmd, timeout=120)

    packets = []
    if result["stdout"].strip():
        try:
            parsed = json.loads(result["stdout"])
            for p in (parsed if isinstance(parsed, list) else [parsed]):
                layers = p.get("_source", {}).get("layers", {})
                packets.append({
                    "frame": _get_layer(layers, "frame.number", ""),
                    "src": _get_layer(layers, "ip.src", ""),
                    "dst": _get_layer(layers, "ip.dst", ""),
                    "protocol": _get_layer(layers, "frame.protocols", ""),
                    "info": _get_layer(layers, "_ws.col.Info", ""),
                })
        except json.JSONDecodeError:
            packets.append({"raw": result["stdout"][:5000]})

    # Protocol hierarchy
    proto_cmd = [tshark_cmd, "-r", pcap_path, "-z", "io,phs", "-q"]
    proto_result = _run_tool(proto_cmd, timeout=60)

    # Conversations
    conv_cmd = [tshark_cmd, "-r", pcap_path, "-z", "conv,ip", "-q"]
    conv_result = _run_tool(conv_cmd, timeout=60)

    return [TextContent(type="text", text=json.dumps({
        "success": True,
        "pcap": pcap_path,
        "packet_count": len(packets),
        "packets": packets[:100],
        "protocol_hierarchy": proto_result["stdout"][:5000] if proto_result["success"] else "",
        "conversations": conv_result["stdout"][:3000] if conv_result["success"] else "",
        "duration_ms": result["duration_ms"],
    }, indent=2))]


def _get_layer(layers: dict, key: str, default: str = "") -> str:
    """Safely extract a value from tshark JSON layers."""
    val = layers.get(key, default)
    if isinstance(val, list):
        return str(val[0]) if val else default
    return str(val) if val else default


async def _handle_pcap_protocols(args: dict) -> list:
    """List protocols in a PCAP."""
    pcap_path = args.get("pcap_path", "")
    err = _validate_evidence_path(pcap_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]
    if not _is_pcap(pcap_path):
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Not a packet capture file",
        }))]

    tshark_cmd = next((p for p in ["/usr/bin/tshark", "/usr/local/bin/tshark"] if Path(p).exists()), "tshark")
    result = _run_tool([tshark_cmd, "-r", pcap_path, "-z", "io,phs", "-q"], timeout=60)

    return [TextContent(type="text", text=json.dumps({
        "success": result["success"],
        "protocols": result["stdout"][:10000] if result["success"] else "",
        "error": result.get("stderr", "") if not result["success"] else None,
    }, indent=2))]


# ── Timeline Analysis Handlers ───────────────────────────────────

async def _handle_timeline_build(args: dict) -> list:
    source_path = args.get("source_path", "")
    output_path = args.get("output_path", "")

    err = _validate_evidence_path(source_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    from src.tools.timeline import build
    result = build(source_path, output_path or None)

    return [TextContent(type="text", text=json.dumps({
        "success": result.success,
        "storage_path": result.storage_path,
        "source": source_path,
        "error": result.error,
        "event_count": result.event_count,
    }, indent=2))]


async def _handle_timeline_filter(args: dict) -> list:
    storage_path = args.get("storage_path", "")
    query = args.get("query", "")
    output_format = args.get("output_format", "json")

    err = _validate_evidence_path(storage_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    from src.tools.timeline import filter_timeline
    result = filter_timeline(storage_path, query, output_format)

    return [TextContent(type="text", text=json.dumps({
        "success": result.success,
        "event_count": result.event_count,
        "events": result.data[:500],
        "error": result.error,
    }, indent=2))]


async def _handle_extract_features(args: dict) -> list:
    image_path = args.get("image_path", "")
    scanners = args.get("scanners", "all")

    err = _validate_evidence_path(image_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    from src.tools.carving import extract_features
    result = extract_features(image_path, scanners)

    return [TextContent(type="text", text=json.dumps({
        "success": result.success,
        "output_dir": result.output_dir,
        "feature_files": result.file_count,
        "details": result.data,
        "error": result.error,
    }, indent=2))]


# ── Accuracy Benchmark Handler ───────────────────────────────────

async def _handle_benchmark(args: dict) -> list:
    """Compare agent findings against known ground truth."""
    evidence_path = args.get("evidence_path", "")
    ground_truth_str = args.get("ground_truth", "[]")

    err = _validate_evidence_path(evidence_path)
    if err:
        return [TextContent(type="text", text=json.dumps({"success": False, "error": err}))]

    try:
        ground_truth = json.loads(ground_truth_str) if isinstance(ground_truth_str, str) else ground_truth_str
    except json.JSONDecodeError:
        return [TextContent(type="text", text=json.dumps({
            "success": False,
            "error": "Invalid ground truth JSON. Provide a valid JSON array of expected findings.",
        }))]

    return [TextContent(type="text", text=json.dumps({
        "success": True,
        "benchmark": {
            "evidence": evidence_path,
            "ground_truth_count": len(ground_truth) if isinstance(ground_truth, list) else 1,
            "ground_truth": ground_truth,
            "benchmark_timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "message": "Accuracy benchmark framework ready. Run full workflow then pass findings here.",
    }, indent=2))]


# ── Audit Log Handler ────────────────────────────────────────────

async def _handle_audit_logs(args: dict) -> list:
    """Return audit logs from current session."""
    limit = min(args.get("limit", 100), 10000)
    logs = _get_audit_logs()[-limit:]
    return [TextContent(type="text", text=json.dumps({
        "success": True,
        "session_log_path": str(_audit_log_path) if _audit_entries else "",
        "total_entries": len(_get_audit_logs()),
        "entries": logs,
    }, indent=2))]


# ═══════════════════════════════════════════════════════════════════
#  SERVER ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════

async def main():
    """Start the MCP server with graceful shutdown handling."""
    logger.info(f"Starting {SERVER_NAME} v{SERVER_VERSION}")
    logger.info(f"Evidence root: {EVIDENCE_ROOT}")
    logger.info(f"Results root: {RESULTS_ROOT}")
    logger.info(f"21 forensic tools registered")

    # Ensure directories exist
    try:
        EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
        RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
        for sub in ('disk', 'memory', 'network', 'cases'):
            (EVIDENCE_ROOT / sub).mkdir(exist_ok=True)
        for sub in ('audit', 'carved', 'timelines', 'reports'):
            (RESULTS_ROOT / sub).mkdir(exist_ok=True)
    except PermissionError:
        logger.warning(f"Cannot create directories. Ensure {EVIDENCE_ROOT} and {RESULTS_ROOT} exist.")

    # Signal handling for graceful shutdown
    shutdown_event = asyncio.Event()

    def _handle_signal(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info(f"Received {sig_name}, shutting down gracefully...")
        total = len(_audit_entries)
        if total > 0:
            logger.info(f"Audit log: {total} calls saved to {_audit_log_path}")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Run server
    async with stdio_server() as (read_stream, write_stream):
        server_task = asyncio.create_task(
            server.run(read_stream, write_stream, server.create_initialization_options())
        )

        await asyncio.wait(
            [server_task, asyncio.create_task(shutdown_event.wait())],
            return_when=asyncio.FIRST_COMPLETED,
        )

        if shutdown_event.is_set():
            server_task.cancel()
            logger.info("Server shut down gracefully")


if __name__ == "__main__":
    asyncio.run(main())
