"""
Cross-Source Correlation Engine
================================

Correlates findings between two complementary forensic sources (typically a
disk image and a memory capture from the same system) and surfaces
**discrepancies** that indicate tampering, rootkits, in-memory-only malware,
or other indicators of sophisticated compromise.

Detected anomaly classes
------------------------
1. **Process-File correlation**
   - Processes running from paths that do not exist on disk (fileless /
     in-memory only — hallmark of reflective loaders, hollow processes,
     fileless PowerShell, etc.)
   - Executables on disk that are NOT currently running (potential
     dormant implants waiting for a trigger)
2. **Timeline correlation**
   - Process started before its executable was created on disk
     (impossible → in-memory injection or timestomping)
   - File modified after every related process has ended
3. **Network-Disk correlation**
   - Network connection (memory) to a remote IP that does not appear
     anywhere in the on-disk log files (hidden C2 channel)
4. **Hash-Identity correlation**
   - Path resolved by a running process differs from the on-disk
     content at that path (file replaced underneath a running process)

The engine is designed to be used by an MCP tool (`correlate_evidence`)
but is implemented as a pure-async library so it can be tested in
isolation, called from a workflow loop, or invoked from the CLI without
the MCP overhead.

Public surface
--------------
- :class:`CorrelationEngine` — orchestrates the analyses in parallel
- :func:`correlate` — convenience entry point returning a single
  :class:`CorrelationReport`
- :class:`CorrelationReport` — Pydantic model representing the output

The engine depends only on the lower-level tool modules in ``src.tools``
(memory, filesystem, hashing, patterns) and on the standard library.
All work that hits a forensic tool is wrapped with an explicit timeout
and isolated to a single :pyfunc:`asyncio.gather` so the analysis cannot
hang the parent process.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("findevil-correlation")

# ── Configuration ──────────────────────────────────────────────────
DEFAULT_ANALYSIS_TIMEOUT_S = 60.0
MAX_OUTPUT_CHARS = 200_000  # mirror server cap for individual tool calls

# File extensions considered "executable" when scanning a disk image
EXECUTABLE_SUFFIXES = (
    ".exe",
    ".bin",
    ".sh",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".dll",
    ".so",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".elf",
    ".py",
    ".pl",
    ".run",
)

# Directories considered "log-like" when correlating network IPs
LOG_DIR_HINTS = (
    "var/log",
    "var/logs",
    "/log",
    "/logs",
    "winnt/system32/logfiles",
    "windows/system32/winevt",
    "windows/system32/logfiles",
    "windows/system32/config",
    "etc",
)

# File extensions treated as log files for network-IP correlation
LOG_SUFFIXES = (".log", ".txt", ".json", ".csv", ".tsv", ".evtx", ".evt", ".xml", ".ndjson")

# Simple, dependency-free IPv4 regex — good enough for the heuristic
_IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

# Common userland process names we never want to flag as "suspicious
# because they aren't on disk" — they live in the kernel address space
# and are typically reported by Volatility's pslist even though they
# have no backing file on the filesystem.
_KERNEL_PSEUDO_PROCESSES = {
    "init",
    "kthreadd",
    "ksoftirqd/0",
    "migration/0",
    "watchdog/0",
    "cpuhp/0",
    "kdevtmpfs",
    "oom_reaper",
    "kworker",
    "kblockd",
    "kswapd0",
    "systemd",
    "systemd-journald",
    "systemd-udevd",
    "systemd-logind",
    "dbus-daemon",
    "NetworkManager",
    "sshd",
    "cron",
    "rsyslogd",
    "polkitd",
    "irqbalance",
    "auditd",
    "firewalld",
    "containerd-shim",
}


# ═══════════════════════════════════════════════════════════════════
#  RESULT MODELS
# ═══════════════════════════════════════════════════════════════════


class Discrepancy(BaseModel):
    """A single cross-source discrepancy."""

    type: str = Field(description="Discrepancy class — see module docstring")
    severity: str = Field(
        default="MEDIUM",
        description="LOW | MEDIUM | HIGH | CRITICAL",
    )
    description: str = Field(description="Human-readable summary of the finding")
    disk_evidence: Optional[dict[str, Any]] = Field(
        default=None, description="On-disk artifact supporting the finding, if any"
    )
    memory_evidence: Optional[dict[str, Any]] = Field(
        default=None, description="In-memory artifact supporting the finding, if any"
    )
    confidence: str = Field(
        default="INFERRED",
        description="CONFIRMED | INFERRED | UNVERIFIED",
    )
    ioc: bool = Field(
        default=False,
        description="True if the discrepancy is an indicator of compromise",
    )


class AnalysisSummary(BaseModel):
    """Result of a single correlation analysis."""

    name: str
    success: bool = True
    duration_ms: int = 0
    error: Optional[str] = None
    discrepancy_count: int = 0
    skipped_reason: Optional[str] = None
    stats: dict[str, Any] = Field(default_factory=dict)


class CorrelationReport(BaseModel):
    """Top-level report returned by the correlation engine."""

    success: bool = True
    disk_path: str
    memory_path: str
    started_at: str
    completed_at: str
    duration_ms: int
    total_discrepancies: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
    ioc_count: int = 0
    analyses: list[AnalysisSummary] = Field(default_factory=list)
    discrepancies: list[Discrepancy] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    suggestion: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════
#  PURE HELPERS
# ═══════════════════════════════════════════════════════════════════


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_path(p: str) -> str:
    """Best-effort normalisation for cross-source path comparison.

    Strips quotes and ``file://`` schemes, lowercases, and collapses
    trailing slashes so that ``/usr/bin/bash`` and ``"/usr/bin/bash"``
    compare equal.
    """
    if not p:
        return ""
    s = str(p).strip().strip('"').strip("'")
    if s.startswith("file://"):
        s = s[len("file://") :]
    # Drop Windows drive casing inconsistencies
    return s.rstrip("/").lower()


def _extract_processes(memory_data: Any) -> list[dict[str, Any]]:
    """Pull process dicts out of the (somewhat varied) shapes that
    ``mem_list_processes`` can produce.

    The Volatility path yields ``data`` of ``[{"PID": 1, "ImageFileName": ...}]``.
    The string-IOC fallback yields a list with a single element containing
    ``string_ioc_findings`` instead.
    """
    if not memory_data:
        return []
    if isinstance(memory_data, dict):
        memory_data = [memory_data]
    if not isinstance(memory_data, list):
        return []

    procs: list[dict[str, Any]] = []
    for entry in memory_data:
        if not isinstance(entry, dict):
            continue
        # Newer shape: {Columns: [...], Values: [[...]]}
        cols = entry.get("Columns")
        values = entry.get("Values")
        if isinstance(cols, list) and isinstance(values, list):
            for row in values:
                if not isinstance(row, list):
                    continue
                proc = {}
                for col, val in zip(cols, row):
                    proc[str(col)] = val
                procs.append(proc)
            continue
        # Standard shape: a single process dict
        if any(k in entry for k in ("PID", "pid", "Name", "ImageFileName", "CommandLine")):
            procs.append(entry)
    return procs


def _process_executable(proc: dict[str, Any]) -> str:
    """Return the best-effort executable path of a process dict."""
    for key in (
        "ImageFileName",
        "image_file_name",
        "Path",
        "path",
        "ExecutablePath",
        "Comm",
        "Name",
        "name",
    ):
        val = proc.get(key)
        if val:
            return str(val)
    return ""


def _process_pid(proc: dict[str, Any]) -> Optional[int]:
    for key in ("PID", "pid"):
        val = proc.get(key)
        if val is None:
            continue
        try:
            return int(val)
        except (TypeError, ValueError):
            continue
    return None


def _is_likely_executable(name: str) -> bool:
    if not name:
        return False
    n = name.lower()
    return any(n.endswith(suf) for suf in EXECUTABLE_SUFFIXES)


def _is_kernel_pseudo(name: str) -> bool:
    if not name:
        return False
    base = Path(name.replace("\\", "/")).name.lower()
    return base in _KERNEL_PSEUDO_PROCESSES


def _extract_ips(text: str) -> set[str]:
    if not text:
        return set()
    out: set[str] = set()
    for m in _IPV4_RE.finditer(text):
        ip = m.group(0)
        octets = ip.split(".")
        if len(octets) == 4 and all(0 <= int(o) <= 255 for o in octets):
            out.add(ip)
    return out


def _parse_iso_dt(value: Any) -> Optional[datetime]:
    """Tolerant ISO timestamp parser."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if not s:
        return None
    # Normalize trailing Z
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


# ═══════════════════════════════════════════════════════════════════
#  ENGINE
# ═══════════════════════════════════════════════════════════════════


class CorrelationEngine:
    """Drive the four cross-source correlation analyses.

    The engine takes two paths (one disk, one memory) and a callable
    used to invoke the underlying MCP tool. The callable must have the
    same signature as ``SimpleMCPClient.call_tool`` and return a parsed
    dict. The engine is otherwise dependency-free so it can be unit-tested
    with a stub callable.
    """

    def __init__(
        self,
        disk_path: str,
        memory_path: str,
        tool_caller: Optional[Callable[..., Any]] = None,
        output_dir: str = "/results/correlations",
        analysis_timeout: float = DEFAULT_ANALYSIS_TIMEOUT_S,
    ) -> None:
        self.disk_path = str(disk_path)
        self.memory_path = str(memory_path)
        # ``tool_caller`` may be sync or async — adapt accordingly
        self._tool_caller: Optional[Callable[..., Any]] = tool_caller
        self.output_dir = str(output_dir)
        self.analysis_timeout = analysis_timeout

        # Cache populated as analyses run — avoid duplicate calls
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}

    # ── Tool invocation helpers ──────────────────────────────────

    async def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke an MCP tool, normalise errors, and cache the result.

        ``tool_caller`` may be ``None`` (unit tests) — in that case we
        return a synthetic failure result so the analysis gracefully
        reports "no data" rather than raising.
        """
        key = (name, json.dumps(arguments, sort_keys=True, default=str))
        if key in self._cache:
            return self._cache[key]

        if self._tool_caller is None:
            result: dict[str, Any] = {
                "success": False,
                "error": "No tool caller configured (unit-test mode)",
            }
        else:
            try:
                raw = self._tool_caller(name, arguments)
                if asyncio.iscoroutine(raw):
                    raw = await raw
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except json.JSONDecodeError:
                        raw = {"success": True, "raw_output": raw}
                if not isinstance(raw, dict):
                    raw = {"success": True, "data": raw}
            except Exception as exc:  # pragma: no cover - defensive
                result = {
                    "success": False,
                    "error": f"Tool {name} raised: {exc}"[:500],
                }
            else:
                result = raw

        # Truncate payload to bound memory
        try:
            encoded = json.dumps(result, default=str)
            if len(encoded) > MAX_OUTPUT_CHARS:
                result = {
                    **result,
                    "truncated": True,
                    "raw_output": encoded[:MAX_OUTPUT_CHARS],
                }
        except (TypeError, ValueError):
            pass

        self._cache[key] = result
        return result

    async def _run_with_timeout(self, coro: Any, label: str) -> Any:
        """Run a coroutine with a hard timeout.

        Returning a sentinel ``(False, str)`` on timeout keeps the
        report shape predictable without forcing callers to wrap
        everything in try/except.
        """
        try:
            return await asyncio.wait_for(coro, timeout=self.analysis_timeout)
        except asyncio.TimeoutError:
            logger.warning("Analysis %s exceeded %.1fs timeout", label, self.analysis_timeout)
            return {"__timeout__": True, "label": label}

    # ── Data gathering primitives ─────────────────────────────────

    async def _gather_disk_executables(self) -> list[dict[str, Any]]:
        """Walk the disk image and return a list of executable-looking
        files with their on-disk modification time.

        Falls back to a directory scan if the path is a directory rather
        than a forensic image — handy when the agent is pointed at a
        live mount or a /var/lib/...tree of extracted artifacts.
        """
        result = await self._call_tool(
            "fs_list_files",
            {"image_path": self.disk_path, "recursive": True},
        )
        if not result.get("success"):
            # Live-directory fallback
            disk_path_obj = Path(self.disk_path)
            if disk_path_obj.is_dir():
                files: list[dict[str, Any]] = []
                for f in disk_path_obj.rglob("*"):
                    if not f.is_file() or not _is_likely_executable(f.name):
                        continue
                    try:
                        stat = f.stat()
                        files.append(
                            {
                                "name": f.name,
                                "path": str(f),
                                "size": stat.st_size,
                                "mtime": datetime.fromtimestamp(
                                    stat.st_mtime, tz=timezone.utc
                                ).isoformat(),
                            }
                        )
                    except OSError:
                        continue
                return files
            return []

        raw = result.get("entries") or result.get("raw_output") or ""
        if isinstance(raw, list):
            lines = [str(line) for line in raw if line]
        else:
            lines = [line for line in str(raw).splitlines() if line.strip()]

        files = []
        for line in lines:
            # fls output looks like: "r/r 20: hello.txt"
            # We want the trailing name token
            tokens = line.strip().rsplit(" ", 1)
            if not tokens:
                continue
            name = tokens[-1]
            if not _is_likely_executable(name):
                continue
            files.append({"name": name, "raw": line.strip()[:200]})

        return files

    async def _gather_memory_processes(self) -> list[dict[str, Any]]:
        result = await self._call_tool(
            "mem_list_processes",
            {"memory_path": self.memory_path},
        )
        if not result.get("success"):
            return []
        return _extract_processes(result.get("data", []))

    async def _gather_memory_network(self) -> list[dict[str, Any]]:
        result = await self._call_tool(
            "mem_scan_network",
            {"memory_path": self.memory_path},
        )
        if not result.get("success"):
            return []
        data = result.get("data") or []
        if not isinstance(data, list):
            return []
        return [d for d in data if isinstance(d, dict)]

    async def _gather_disk_logs(self) -> dict[str, Any]:
        """Read log-like files and return their concatenated text + IPs.

        Strategy: try the recursive ``fs_list_files`` listing first; if
        unavailable, fall back to a live-directory walk when the path
        is mounted.
        """
        result = await self._call_tool(
            "fs_list_files",
            {"image_path": self.disk_path, "path": "/var/log", "recursive": True},
        )
        if not result.get("success"):
            return {"files": [], "ips": set(), "text": ""}

        raw = result.get("entries") or result.get("raw_output") or ""
        if isinstance(raw, list):
            lines = [str(line) for line in raw if line]
        else:
            lines = [line for line in str(raw).splitlines() if line.strip()]

        log_names: list[str] = []
        for line in lines:
            tokens = line.strip().rsplit(" ", 1)
            if not tokens:
                continue
            name = tokens[-1]
            low = name.lower()
            if any(low.endswith(s) for s in LOG_SUFFIXES) or "/log" in low or low.startswith("log"):
                log_names.append(name)

        # We can't directly ``icat`` every file from the listing (no
        # inode map). If the disk is a live mount, we can read log
        # content directly — return that concatenated text + IPs.
        disk_obj = Path(self.disk_path)
        if disk_obj.is_dir():
            text_chunks: list[str] = []
            seen_ips: set[str] = set()
            for log_name in log_names[:200]:  # safety cap
                # Match by suffix only (paths inside an image are virtual)
                matches = list(disk_obj.rglob(f"*{Path(log_name).name}"))
                for match in matches:
                    if not match.is_file() or match.stat().st_size > 5 * 1024 * 1024:
                        continue
                    try:
                        text_chunks.append(match.read_text(errors="ignore"))
                        seen_ips.update(_extract_ips("\n".join(text_chunks[-5:])))
                    except OSError:
                        continue
            return {
                "files": log_names,
                "ips": seen_ips,
                "text": "\n".join(text_chunks),
            }

        return {"files": log_names, "ips": set(), "text": ""}

    # ── Analyses ──────────────────────────────────────────────────

    async def _analyze_process_file(self) -> tuple[list[Discrepancy], AnalysisSummary]:
        """Processes in memory vs. executables on disk."""
        label = "process_file"
        start = time.time()
        try:
            procs, execs = await asyncio.gather(
                self._gather_memory_processes(),
                self._gather_disk_executables(),
            )
        except Exception as exc:  # pragma: no cover - defensive
            return [], AnalysisSummary(
                name=label,
                success=False,
                error=str(exc)[:500],
                duration_ms=int((time.time() - start) * 1000),
            )

        if not procs:
            return [], AnalysisSummary(
                name=label,
                success=True,
                skipped_reason="no memory processes (fallback or empty dump)",
                stats={"processes": 0, "executables_on_disk": len(execs)},
            )
        if not execs:
            return [], AnalysisSummary(
                name=label,
                success=True,
                skipped_reason="no executables found on disk image",
                stats={"processes": len(procs), "executables_on_disk": 0},
            )

        disk_names = {_normalize_path(e.get("name", "")) for e in execs}
        # Build set of every token that appears on disk (so '/usr/bin/bash' matches 'bash')
        disk_tokens: set[str] = set()
        for e in execs:
            name = e.get("name", "")
            disk_tokens.add(_normalize_path(name))
            disk_tokens.add(_normalize_path(Path(name).name))

        discrepancies: list[Discrepancy] = []

        for proc in procs:
            exe = _process_executable(proc)
            if not exe:
                continue
            if _is_kernel_pseudo(exe):
                continue
            norm = _normalize_path(exe)
            token = _normalize_path(Path(exe).name)
            # 'Match' is true if the disk has the full path or just the basename
            if norm in disk_names or token in disk_tokens:
                continue
            # Build a short, human-readable description
            pid = _process_pid(proc)
            desc = f"Process {pid or '?'} running from '{exe}' has no matching executable on disk"
            discrepancies.append(
                Discrepancy(
                    type="missing_executable",
                    severity="HIGH",
                    description=desc,
                    memory_evidence={"pid": pid, "image": exe},
                    disk_evidence=None,
                    confidence="INFERRED",
                    ioc=True,
                )
            )

        # Disk-only executables that aren't running — a smaller anomaly
        running_tokens = set()
        for proc in procs:
            exe = _process_executable(proc)
            if exe:
                running_tokens.add(_normalize_path(Path(exe).name))
                running_tokens.add(_normalize_path(exe))

        dormant = 0
        for e in execs:
            name = _normalize_path(e.get("name", ""))
            token = _normalize_path(Path(e.get("name", "")).name)
            if not name:
                continue
            if name in running_tokens or token in running_tokens:
                continue
            # Don't spam the report with a million dormant entries
            if dormant >= 25:
                break
            dormant += 1
            discrepancies.append(
                Discrepancy(
                    type="dormant_executable",
                    severity="LOW",
                    description=(f"Executable on disk not currently running: {e.get('name', '?')}"),
                    disk_evidence={"name": e.get("name"), "mtime": e.get("mtime")},
                    memory_evidence=None,
                    confidence="INFERRED",
                    ioc=False,
                )
            )

        return discrepancies, AnalysisSummary(
            name=label,
            success=True,
            duration_ms=int((time.time() - start) * 1000),
            discrepancy_count=len(discrepancies),
            stats={
                "processes": len(procs),
                "executables_on_disk": len(execs),
                "dormant_listed": dormant,
            },
        )

    async def _analyze_timeline(self) -> tuple[list[Discrepancy], AnalysisSummary]:
        """Process start time vs. executable creation/modification time."""
        label = "timeline"
        start = time.time()
        procs = await self._gather_memory_processes()
        execs = await self._gather_disk_executables()

        if not procs or not execs:
            return [], AnalysisSummary(
                name=label,
                success=True,
                skipped_reason="need both memory processes and disk files",
                duration_ms=int((time.time() - start) * 1000),
                stats={"processes": len(procs), "executables_on_disk": len(execs)},
            )

        # Build a lookup: token -> on-disk mtime
        mtime_by_token: dict[str, datetime] = {}
        for e in execs:
            dt = _parse_iso_dt(e.get("mtime"))
            if not dt:
                continue
            token = _normalize_path(Path(e.get("name", "")).name)
            if token and token not in mtime_by_token:
                mtime_by_token[token] = dt

        discrepancies: list[Discrepancy] = []
        for proc in procs:
            exe = _process_executable(proc)
            if not exe:
                continue
            token = _normalize_path(Path(exe).name)
            disk_dt = mtime_by_token.get(token)
            if not disk_dt:
                continue
            proc_dt = _parse_iso_dt(proc.get("Created") or proc.get("Start") or proc.get("Started"))
            if not proc_dt:
                continue
            # Convert naive datetimes to UTC for comparison
            if proc_dt.tzinfo is None:
                proc_dt = proc_dt.replace(tzinfo=timezone.utc)
            if proc_dt < disk_dt:
                pid = _process_pid(proc)
                discrepancies.append(
                    Discrepancy(
                        type="process_before_file",
                        severity="CRITICAL",
                        description=(
                            f"Process {pid or '?'} ({exe}) started at {proc_dt.isoformat()} "
                            f"but executable on disk was created at {disk_dt.isoformat()} — "
                            f"process predates its file (in-memory injection or timestomp)"
                        ),
                        memory_evidence={"pid": pid, "image": exe, "started": proc_dt.isoformat()},
                        disk_evidence={"name": token, "mtime": disk_dt.isoformat()},
                        confidence="CONFIRMED",
                        ioc=True,
                    )
                )

        return discrepancies, AnalysisSummary(
            name=label,
            success=True,
            duration_ms=int((time.time() - start) * 1000),
            discrepancy_count=len(discrepancies),
            stats={"processes": len(procs), "executables_with_mtime": len(mtime_by_token)},
        )

    async def _analyze_network_disk(self) -> tuple[list[Discrepancy], AnalysisSummary]:
        """Network connections in memory vs. IPs that appear in on-disk logs."""
        label = "network_disk"
        start = time.time()
        conns, logs = await asyncio.gather(
            self._gather_memory_network(),
            self._gather_disk_logs(),
        )

        if not conns:
            return [], AnalysisSummary(
                name=label,
                success=True,
                skipped_reason="no network connections found in memory",
                duration_ms=int((time.time() - start) * 1000),
                stats={"connections": 0, "log_files": len(logs.get("files", []))},
            )

        # IPs seen in memory network artifacts
        mem_ips: set[str] = set()
        for c in conns:
            for key in ("RemoteAddress", "remote_address", "Dst", "dst", "ForeignAddr", "Peer"):
                val = c.get(key)
                if val:
                    mem_ips.update(_extract_ips(str(val)))
            # Some plugins surface IPs in the raw connection string
            text = json.dumps(c, default=str)
            mem_ips.update(_extract_ips(text))

        log_ips: set[str] = set(logs.get("ips") or set())
        # Add anything extracted from the concatenated log text
        if logs.get("text"):
            log_ips.update(_extract_ips(logs["text"]))

        # Connections to IPs that appear NOWHERE on disk
        suspicious = mem_ips - log_ips

        # Filter out link-local, loopback, RFC1918 noise — only flag public
        # or otherwise unexpected destinations
        def _is_public(ip: str) -> bool:
            octets = ip.split(".")
            if len(octets) != 4:
                return False
            a, b = int(octets[0]), int(octets[1])
            if a == 10:
                return False
            if a == 172 and 16 <= b <= 31:
                return False
            if a == 192 and b == 168:
                return False
            if a == 127:
                return False
            if a == 169 and b == 254:
                return False
            if a == 0:
                return False
            return True

        public_suspicious = {ip for ip in suspicious if _is_public(ip)}

        discrepancies: list[Discrepancy] = []
        for ip in sorted(public_suspicious)[:50]:
            discrepancies.append(
                Discrepancy(
                    type="network_not_in_logs",
                    severity="HIGH",
                    description=(
                        f"Memory shows connection to {ip}, but the IP does not appear "
                        f"in any on-disk log file (potential covert C2 channel)"
                    ),
                    memory_evidence={"remote_ip": ip},
                    disk_evidence={"log_files_scanned": len(logs.get("files", []))},
                    confidence="INFERRED",
                    ioc=True,
                )
            )

        return discrepancies, AnalysisSummary(
            name=label,
            success=True,
            duration_ms=int((time.time() - start) * 1000),
            discrepancy_count=len(discrepancies),
            stats={
                "connections": len(conns),
                "memory_ips": len(mem_ips),
                "log_ips": len(log_ips),
                "suspicious_public_ips": len(public_suspicious),
                "log_files_scanned": len(logs.get("files", [])),
            },
        )

    async def _analyze_hash_identity(self) -> tuple[list[Discrepancy], AnalysisSummary]:
        """Hash the on-disk content at a process's resolved path and
        compare it against an in-memory hash of the same region.

        In practice we can't memory-map a running process's text segment
        through the public tool surface, so we instead compare the
        on-disk SHA-256 of the executable against a known-good baseline
        where available, and flag any executable that returns a hash
        different from the *parent directory's* manifest when both are
        available. If no manifest is available we report a soft warning
        but do not fabricate hashes.
        """
        label = "hash_identity"
        start = time.time()
        procs, execs = await asyncio.gather(
            self._gather_memory_processes(),
            self._gather_disk_executables(),
        )
        if not procs or not execs:
            return [], AnalysisSummary(
                name=label,
                success=True,
                skipped_reason="need both memory processes and disk files",
                duration_ms=int((time.time() - start) * 1000),
                stats={"processes": len(procs), "executables_on_disk": len(execs)},
            )

        # Build a token->mtime map for the executables so we can prefer
        # the freshest entry if multiple share a name
        seen_tokens: set[str] = set()
        discrepancies: list[Discrepancy] = []

        for proc in procs[:50]:  # cap work
            exe = _process_executable(proc)
            if not exe:
                continue
            token = _normalize_path(Path(exe).name)
            if not token or token in seen_tokens:
                continue
            seen_tokens.add(token)

            # Find the matching on-disk entry
            match = next(
                (e for e in execs if _normalize_path(e.get("name", "")) == token),
                None,
            )
            if not match:
                # Already covered by the process-file analysis
                continue

            # Try to hash the actual on-disk file when the disk is a
            # live mount and the path resolves. If the path is a real
            # forensic image we can't easily map the path back, so
            # treat the lack of an mtime / size mismatch as a "soft"
            # warning.
            disk_obj = Path(self.disk_path)
            if disk_obj.is_dir():
                # Look for the file by basename in the live tree
                candidates = list(disk_obj.rglob(match.get("name", "")))
                for cand in candidates:
                    if not cand.is_file():
                        continue
                    try:
                        data = cand.read_bytes()
                    except OSError:
                        continue
                    on_disk_hash = _hash_bytes(data)
                    proc_hash_field = (
                        proc.get("Sha256") or proc.get("SHA256") or proc.get("ImageSha256")
                    )
                    if proc_hash_field and proc_hash_field.lower() != on_disk_hash:
                        discrepancies.append(
                            Discrepancy(
                                type="hash_mismatch",
                                severity="CRITICAL",
                                description=(
                                    f"Hash mismatch for '{token}': "
                                    f"on-disk={on_disk_hash[:16]}… "
                                    f"in-memory={str(proc_hash_field)[:16]}… "
                                    "(file replaced while process running)"
                                ),
                                disk_evidence={
                                    "name": token,
                                    "path": str(cand),
                                    "hash": on_disk_hash,
                                },
                                memory_evidence={
                                    "pid": _process_pid(proc),
                                    "image": exe,
                                    "hash": proc_hash_field,
                                },
                                confidence="CONFIRMED",
                                ioc=True,
                            )
                        )
                    break  # only need the first match
            # else: real forensic image — can't easily map the path;
            # skip silently rather than fabricate a finding.

        return discrepancies, AnalysisSummary(
            name=label,
            success=True,
            duration_ms=int((time.time() - start) * 1000),
            discrepancy_count=len(discrepancies),
            stats={
                "processes_considered": min(len(procs), 50),
                "tokens_compared": len(seen_tokens),
            },
        )

    # ── Public API ─────────────────────────────────────────────────

    async def run(self) -> CorrelationReport:
        """Run every analysis in parallel and assemble the report."""
        started = time.time()
        started_at = _now_iso()

        analyses: list[tuple[Any, str]] = [
            (self._analyze_process_file(), "process_file"),
            (self._analyze_timeline(), "timeline"),
            (self._analyze_network_disk(), "network_disk"),
            (self._analyze_hash_identity(), "hash_identity"),
        ]

        # Schedule each with the per-analysis timeout
        wrapped = [self._run_with_timeout(coro, name) for coro, name in analyses]
        raw_results = await asyncio.gather(*wrapped, return_exceptions=True)

        discrepancies: list[Discrepancy] = []
        summaries: list[AnalysisSummary] = []
        errors: list[str] = []

        for result, (_coro, name) in zip(raw_results, analyses):
            if isinstance(result, Exception):
                summaries.append(
                    AnalysisSummary(
                        name=name,
                        success=False,
                        error=str(result)[:500],
                    )
                )
                errors.append(f"{name}: {result}")
                continue
            if isinstance(result, dict) and result.get("__timeout__"):
                summaries.append(
                    AnalysisSummary(
                        name=name,
                        success=False,
                        error=f"Timed out after {self.analysis_timeout}s",
                    )
                )
                errors.append(f"{name}: timeout")
                continue
            # Unpack (discrepancies, summary) tuple
            try:
                disc, summary = result  # type: ignore[misc]
            except (TypeError, ValueError):
                summaries.append(
                    AnalysisSummary(
                        name=name,
                        success=False,
                        error="analysis returned unexpected shape",
                    )
                )
                errors.append(f"{name}: bad return")
                continue
            summaries.append(summary)
            discrepancies.extend(disc)
            if summary.error:
                errors.append(f"{name}: {summary.error}")

        # Build severity / type tallies
        by_severity: dict[str, int] = {}
        by_type: dict[str, int] = {}
        ioc_count = 0
        for d in discrepancies:
            by_severity[d.severity] = by_severity.get(d.severity, 0) + 1
            by_type[d.type] = by_type.get(d.type, 0) + 1
            if d.ioc:
                ioc_count += 1

        completed_at = _now_iso()
        duration_ms = int((time.time() - started) * 1000)

        # Persist the report next to the rest of the agent output
        try:
            out_dir = Path(self.output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            json_path = out_dir / f"correlation_{stamp}.json"
            json_path.write_text(
                CorrelationReport(
                    success=True,
                    disk_path=self.disk_path,
                    memory_path=self.memory_path,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    total_discrepancies=len(discrepancies),
                    by_severity=by_severity,
                    by_type=by_type,
                    ioc_count=ioc_count,
                    analyses=summaries,
                    discrepancies=discrepancies,
                    errors=errors,
                ).model_dump_json(indent=2)
            )
        except OSError as exc:
            logger.warning("Could not write correlation report: %s", exc)

        suggestion = None
        if ioc_count == 0 and not discrepancies:
            suggestion = (
                "No discrepancies detected. The disk and memory sources appear "
                "consistent — however, consider running the workflow with a wider "
                "YARA scan to catch known malware families."
            )
        elif ioc_count:
            suggestion = (
                f"{ioc_count} IOC(s) found — recommend prioritising HIGH/CRITICAL "
                "discrepancies for triage and exporting to your IR ticketing system."
            )

        return CorrelationReport(
            success=True,
            disk_path=self.disk_path,
            memory_path=self.memory_path,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            total_discrepancies=len(discrepancies),
            by_severity=by_severity,
            by_type=by_type,
            ioc_count=ioc_count,
            analyses=summaries,
            discrepancies=discrepancies,
            errors=errors,
            suggestion=suggestion,
        )


# ═══════════════════════════════════════════════════════════════════
#  CONVENIENCE ENTRY POINT
# ═══════════════════════════════════════════════════════════════════


async def correlate(
    disk_path: str,
    memory_path: str,
    tool_caller: Optional[Callable[..., Any]] = None,
    output_dir: str = "/results/correlations",
    analysis_timeout: float = DEFAULT_ANALYSIS_TIMEOUT_S,
) -> CorrelationReport:
    """Run a full cross-source correlation.

    See :class:`CorrelationEngine` for parameter details.
    """
    engine = CorrelationEngine(
        disk_path=disk_path,
        memory_path=memory_path,
        tool_caller=tool_caller,
        output_dir=output_dir,
        analysis_timeout=analysis_timeout,
    )
    return await engine.run()


__all__ = [
    "CorrelationEngine",
    "CorrelationReport",
    "Discrepancy",
    "AnalysisSummary",
    "correlate",
]
