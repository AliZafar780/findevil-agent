"""
Self-Correcting DFIR Agent Loop with Groq LLM integration.
Implements the ReAct pattern: Reason → Act → Observe → Correct → Report
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .groq_client import GroqDFIRClient
from .output_parser import parse_report
from .tool_selector import suggest_next_tools

# ── Evidence Type Detection ──────────────────────────────────────────
# Maps file extensions to evidence categories for tool compatibility filtering.

EVIDENCE_TYPE_MAP: dict[str, list[str]] = {
    # Disk comes first because .raw is overwhelmingly used for disk images in DFIR
    "disk": [".img", ".iso", ".vhd", ".vmdk", ".qcow2", ".ext2", ".ext3", ".ext4", ".raw", ".dd"],
    "memory": [".mem", ".vmem", ".dmp", ".dump", ".bin", ".elf"],
    "pcap": [".pcap", ".pcapng", ".cap"],
    "registry": [".hiv", ".dat", ".reg"],
    "artifact": [".json", ".csv", ".log", ".txt"],
}

# Tools grouped by compatible evidence type
EVIDENCE_TO_TOOLS: dict[str, list[str]] = {
    "memory": ["mem_list_processes", "mem_analyze", "mem_scan_network", "mem_dump_cmdline"],
    "disk": [
        "fs_partition_scan", "fs_list_files", "fs_filesystem_info", "fs_extract_file",
        "carve_files", "extract_features", "analyze_binary",
    ],
    "pcap": ["pcap_analyze", "pcap_list_protocols"],
    "registry": ["reg_analyze_hive"],
    "any": [
        "list_evidence", "verify_hash", "compute_hash", "scan_yara", "search_text_patterns",
        "get_audit_logs", "get_security_logs", "fs_strings", "timeline_build",
        "timeline_filter", "extract_features",
    ],
}


def _detect_evidence_type(evidence_path: str) -> str:
    """Detect evidence type from file extension.

    Returns one of: 'memory', 'disk', 'pcap', 'registry', 'artifact', or 'unknown'.
    """
    if not evidence_path:
        return "unknown"
    path = evidence_path.lower()
    for etype, exts in EVIDENCE_TYPE_MAP.items():
        for ext in exts:
            if path.endswith(ext):
                return etype
    # Default heuristic: if it has an extension, treat as disk
    if "." in Path(evidence_path).name:
        return "disk"
    return "unknown"


def _get_compatible_tools(evidence_type: str) -> list[str]:
    """Get tool names compatible with the given evidence type.

    Includes both general-purpose tools ('any' category) and type-specific tools.
    """
    tools = list(EVIDENCE_TO_TOOLS.get("any", []))
    tools.extend(EVIDENCE_TO_TOOLS.get(evidence_type, []))
    return tools


logger = logging.getLogger("findevil-agent")


class ToolCall:
    """Record of a single tool execution."""

    def __init__(self, tool: str, arguments: dict[str, Any], iteration: int) -> None:
        self.tool = tool
        self.arguments = arguments
        self.iteration = iteration
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.success = False
        self.result: Any = None
        self.error: Optional[str] = None
        self.duration_ms = 0
        self.start_time = time.time()

    def complete(self, result: Any, duration: float) -> None:
        self.result = result
        self.duration = duration
        self.duration_ms = int(duration * 1000)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "iteration": self.iteration,
            "tool": self.tool,
            "arguments": self.arguments,
            "success": self.success,
            "duration_ms": self.duration_ms,
            "error": str(self.error) if self.error else None,
        }


class AgentState:
    """Track agent execution state and support self-correction."""

    def __init__(self, max_iterations: int = 30) -> None:
        self.iteration = 0
        self.max_iterations = max_iterations
        self.tool_calls: list[ToolCall] = []
        self.findings: list[dict[str, Any]] = []
        self.consecutive_failures = 0
        self.start_time = time.time()
        self.status = "running"
        self.last_tool_results: dict[str, Any] = {}
        self.errors: list[str] = []

    def should_abort(self) -> tuple[bool, str]:
        """Check if the agent should abort based on iteration count, failures, or elapsed time."""
        if self.iteration >= self.max_iterations:
            return True, f"Max iterations ({self.max_iterations}) reached"
        if self.consecutive_failures >= 5:
            return True, f"{self.consecutive_failures} consecutive tool failures"
        elapsed = time.time() - self.start_time
        if elapsed > 3600:
            return True, f"Time limit exceeded ({int(elapsed)}s)"
        return False, ""

    def record_call(self, tool_call: ToolCall) -> None:
        self.tool_calls.append(tool_call)
        if tool_call.success:
            self.consecutive_failures = 0
            self.last_tool_results[tool_call.tool] = tool_call.result
        else:
            self.consecutive_failures += 1
            self.errors.append(f"{tool_call.tool}: {tool_call.error}")

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.findings.append(finding)

    def get_summary(self) -> dict[str, Any]:
        total = len(self.tool_calls)
        successful = sum(1 for t in self.tool_calls if t.success)
        return {
            "status": self.status,
            "iterations": self.iteration,
            "tool_calls": total,
            "successful_calls": successful,
            "failed_calls": total - successful,
            "findings": len(self.findings),
            "elapsed_seconds": int(time.time() - self.start_time),
        }


class DFIRWorkflow:
    """
    Structured DFIR analysis workflow with Groq-powered self-correction.
    Uses LLM to intelligently select tools and interpret results.
    """

    PHASES = [
        "initial_triage",
        "filesystem_analysis",
        "artifact_extraction",
        "memory_analysis",
        "registry_analysis",
        "network_analysis",
        "cross_reference",
        "reporting",
    ]

    # Default tool chains per phase (used as fallback if LLM is unavailable)
    DEFAULT_TOOLS = {
        "initial_triage": [
            "list_evidence",
            "verify_hash",
            "fs_partition_scan",
            "fs_filesystem_info",
        ],
        "filesystem_analysis": ["fs_list_files", "fs_file_metadata", "fs_extract_file"],
        "artifact_extraction": ["carve_files", "scan_yara"],
        "memory_analysis": [
            "mem_list_processes",
            "mem_analyze",
            "mem_scan_network",
            "mem_dump_cmdline",
        ],
        "registry_analysis": ["reg_analyze_hive"],
        "network_analysis": ["pcap_analyze", "pcap_list_protocols"],
        "cross_reference": ["get_audit_logs", "verify_hash"],
        "reporting": [],
    }

    FALLBACK_CHAINS = {
        "fs_list_files": ["fs_filesystem_info", "fs_partition_scan", "carve_files"],
        "fs_extract_file": ["carve_files", "scan_yara"],
        "fs_partition_scan": ["fs_filesystem_info", "list_evidence"],
        "scan_yara": ["carve_files", "extract_features", "verify_hash"],
        "mem_list_processes": ["mem_analyze", "mem_scan_network"],
        "mem_analyze": ["mem_list_processes", "mem_dump_cmdline"],
        "pcap_analyze": ["pcap_list_protocols"],
        "reg_analyze_hive": ["fs_list_files", "scan_yara"],
    }

    def __init__(self, mcp_client: Any, groq_client: Optional[GroqDFIRClient] = None):
        self.client = mcp_client
        self.groq = groq_client or GroqDFIRClient()
        self.state = AgentState()
        self.current_phase = "initial_triage"
        self._detected_offset = 0
        self._evidence_path = ""
        self.duration: float = 0.0

    async def run(self, task: str, evidence_path: str) -> dict[str, Any]:
        """Execute the complete DFIR workflow across all phases."""
        logger.info(f"Starting DFIR workflow: {task[:200]}" if task else "Starting DFIR workflow")
        logger.info(f"Evidence: {evidence_path[:200]}" if evidence_path else "Evidence: (none)")
        self._evidence_path = evidence_path

        # Pre-validate evidence exists and is accessible (before any tool calls)
        if evidence_path:
            from pathlib import Path as _Path

            ev_path = _Path(evidence_path)
            if not ev_path.exists():
                self.state.status = "aborted"
                return self._build_result(
                    json.dumps(
                        {
                            "summary": "Evidence path does not exist",
                            "findings": [
                                {
                                    "type": "error",
                                    "description": f"Evidence not found: {evidence_path}",
                                }
                            ],
                            "errors": [f"Evidence path does not exist: {evidence_path}"],
                        }
                    )
                )
            if ev_path.is_dir():
                # For directories, check they're non-empty
                try:
                    contents = list(ev_path.iterdir())
                    if not contents:
                        logger.warning(f"Evidence directory is empty: {evidence_path}")
                except PermissionError:
                    self.state.status = "aborted"
                    return self._build_result(
                        json.dumps(
                            {
                                "summary": "Cannot access evidence directory",
                                "findings": [
                                    {
                                        "type": "error",
                                        "description": f"Permission denied: {evidence_path}",
                                    }
                                ],
                            }
                        )
                    )
            elif ev_path.stat().st_size == 0:
                self.state.status = "aborted"
                return self._build_result(
                    json.dumps(
                        {
                            "summary": "Evidence file is empty",
                            "findings": [
                                {"type": "error", "description": f"Empty file: {evidence_path}"}
                            ],
                        }
                    )
                )

        # Log whether LLM is available
        if self.groq.available:
            logger.info("Groq LLM available — using AI-powered analysis")
        else:
            logger.info(
                "Groq LLM NOT available — running in deterministic mode. "
                "Set GROQ_API_KEY for LLM-enhanced analysis."
            )

        self.state.add_finding(
            {
                "type": "case_info",
                "description": f"Case initiated: {task}",
                "task": task,
                "evidence": evidence_path,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "confidence": "CONFIRMED",
            }
        )

        for phase in self.PHASES:
            if self.state.status != "running":
                break
            self.current_phase = phase
            logger.info("━" * 60)
            logger.info(f"  PHASE: {phase}")
            logger.info("━" * 60)

            if phase == "reporting":
                break

            await self._execute_phase()

        # Mark as completed
        self.state.status = "completed"

        # Generate final report using Groq
        report = await self._generate_report()
        return self._build_result(report)

    async def _execute_phase(self) -> None:
        """Execute a single analysis phase."""
        # Auto-detect partition offset
        if (
            self.current_phase in ("initial_triage", "filesystem_analysis")
            and self._detected_offset == 0
        ):
            self._detected_offset = await self._detect_partition_offset()

        # Get tools for this phase
        tools = await self._get_phase_tools()
        logger.info(f"Phase tools: {tools}")

        for tool_name in tools:
            abort, reason = self.state.should_abort()
            if abort:
                self.state.status = "aborted"
                logger.warning(f"Aborting: {reason}")
                return

            self.state.iteration += 1
            tool_call = ToolCall(tool_name, {}, self.state.iteration)

            try:
                start = time.time()
                args = self._build_args(tool_name)
                result = await self.client.call_tool(tool_name, args)
                duration = time.time() - start

                if isinstance(result, str):
                    try:
                        parsed = json.loads(result)
                    except json.JSONDecodeError:
                        parsed = {"success": True, "raw": result[:5000]}
                elif isinstance(result, dict):
                    parsed = result
                else:
                    parsed = {"success": True, "data": str(result)[:5000]}

                tool_call.success = parsed.get("success", True)
                tool_call.complete(parsed, duration)

                if tool_call.success:
                    logger.info(f"  ✅ {tool_name} succeeded ({duration:.2f}s)")
                    self._extract_findings(tool_name, parsed)
                else:
                    logger.warning(f"  ⚠️ {tool_name} failed: {parsed.get('error', 'unknown')}")

            except Exception as e:
                tool_call.error = str(e)
                tool_call.success = False
                tool_call.complete(None, 0)
                logger.warning(f"  ❌ {tool_name} exception: {e}")

                # Self-correction: try fallback tools
                fallbacks = self.FALLBACK_CHAINS.get(tool_name, [])
                for fb in fallbacks:
                    if self.state.consecutive_failures >= 3:
                        break
                    logger.info(f"  ↪ Fallback: {fb}")
                    await self._try_fallback(fb)
                    if self.state.consecutive_failures == 0:
                        break  # Fallback worked

                # Type-aware escalation: if fallbacks also fail, switch tool categories
                if (
                    self.state.consecutive_failures >= 2
                    and self._evidence_path
                    and not tool_call.success
                ):
                    current_type = _detect_evidence_type(self._evidence_path)
                    fallback_order = ["any", "disk", "memory", "pcap", "registry"]
                    for ftype in fallback_order:
                        if ftype == current_type:
                            continue
                        candidates = [
                            t for t in _get_compatible_tools(ftype)
                            if t not in fallbacks
                        ]
                        if candidates:
                            logger.info(
                                f"  ↪ Type escalation: {current_type} -> {ftype}, "
                                f"trying {candidates[0]}"
                            )
                            await self._try_fallback(candidates[0])
                            if self.state.consecutive_failures == 0:
                                break

            self.state.record_call(tool_call)

    async def _get_phase_tools(self) -> list[str]:
        """Get tools for current phase, using LLM when possible, falling back to tool_selector."""
        defaults = self.DEFAULT_TOOLS.get(self.current_phase, [])
        tool_selector_tools = suggest_next_tools(self.current_phase)

        # For first run or when we have results, let LLM decide
        if self.state.last_tool_results and self.current_phase not in ("initial_triage",):
            try:
                llm_decision = self.groq.decide_next_tools(
                    self.current_phase,
                    self.state.last_tool_results,
                    self.state.errors[-3:] if self.state.errors else [],
                )
                if llm_decision:
                    logger.info(f"  🤖 LLM tool selection: {llm_decision}")
                    suggested = [t.get("name", t) if isinstance(t, dict) else t for t in llm_decision]
                    # Filter out tools incompatible with the current evidence type
                    if self._evidence_path:
                        evidence_type = _detect_evidence_type(self._evidence_path)
                        compatible = _get_compatible_tools(evidence_type)
                        filtered = [t for t in suggested if t in compatible]
                        if len(filtered) < len(suggested):
                            removed = set(suggested) - set(filtered)
                            logger.info(
                                f"Filtered {len(removed)} incompatible tools for "
                                f"{evidence_type} evidence: {removed}"
                            )
                        suggested = filtered or suggested  # Fall back to originals if empty
                    return suggested
            except Exception as e:
                logger.warning(f"LLM tool selection failed, using tool_selector fallback: {e}")

        # Fallback to tool_selector's registry (prioritized)
        if tool_selector_tools:
            return [t["tool"] for t in tool_selector_tools]

        return defaults

    async def _detect_partition_offset(self) -> int:
        """Auto-detect the data partition offset from a disk image."""
        try:
            result = await self.client.call_tool(
                "fs_partition_scan", {"image_path": self._evidence_path}
            )
            if isinstance(result, str):
                parsed = json.loads(result)
            else:
                parsed = result

            if parsed.get("success"):
                partitions = parsed.get("partitions", [])
                excluded_descs = {
                    "safety table",
                    "gpt header",
                    "partition table",
                    "unallocated",
                    "meta",
                }
                for p in partitions:
                    desc = p.get("description", "").strip().lower()
                    length = p.get("length", 0)
                    slot = p.get("slot", -1)
                    if slot >= 0 and desc not in excluded_descs and length > 100:
                        logger.info(
                            f"Auto-detected partition offset: {p.get('start', 0)} (slot {slot})"
                        )
                        return p.get("start", 0)  # type: ignore[no-any-return]
            return 0
        except Exception as e:
            logger.warning(f"Failed to detect partition offset: {e}")
            return 0

    def _build_args(self, tool_name: str) -> dict[str, Any]:
        """Build appropriate arguments for each tool."""
        ep = self._evidence_path
        off = self._detected_offset

        arg_map = {
            "list_evidence": {"subdir": "cases"},
            "verify_hash": {"file_path": ep, "algorithm": "sha256"},
            "fs_partition_scan": {"image_path": ep},
            "fs_filesystem_info": {"image_path": ep, "offset": off},
            "fs_list_files": {"image_path": ep, "offset": off},
            "fs_file_metadata": {"image_path": ep, "offset": off, "inode": 20},
            "fs_extract_file": {"image_path": ep, "offset": off, "inode": 20},
            "carve_files": {
                "image_path": ep,
                "file_types": "all",
                "output_dir": "/results/carved/agent",
            },
            "scan_yara": {
                "target": ep,
                "rules": 'rule FindEvil { strings: $a = "malware" nocase condition: $a }',
            },
            "mem_analyze": {"memory_path": ep, "plugin": "windows.pslist.PsList"},
            "mem_list_processes": {"memory_path": ep},
            "mem_scan_network": {"memory_path": ep},
            "mem_dump_cmdline": {"memory_path": ep},
            "reg_analyze_hive": {"hive_path": ep, "key": "/Microsoft/Windows/CurrentVersion/Run"},
            "pcap_analyze": {"pcap_path": ep, "max_packets": 100},
            "pcap_list_protocols": {"pcap_path": ep},
            "get_audit_logs": {"limit": 50},
        }
        return arg_map.get(tool_name, {})  # type: ignore[return-value]

    async def _try_fallback(self, tool_name: str) -> None:
        """Try a fallback tool when primary fails."""
        self.state.iteration += 1
        tool_call = ToolCall(tool_name, {}, self.state.iteration)

        try:
            args = self._build_args(tool_name)
            result = await self.client.call_tool(tool_name, args)
            if isinstance(result, str):
                parsed = json.loads(result)
            elif isinstance(result, dict):
                parsed = result
            else:
                parsed = {"success": True}
            tool_call.success = parsed.get("success", True)
            tool_call.complete(parsed, 0)
            if tool_call.success:
                self._extract_findings(tool_name, parsed)
        except Exception as e:
            tool_call.error = str(e)
            tool_call.success = False

        self.state.record_call(tool_call)

    # ── Confidence Scoring System ───────────────────────────────────
    # Scoring logic: each finding is evaluated on data quality + tool reliability.
    # Higher weight = more likely CONFIRMED. Scoring based on concrete output data.

    _CONFIDENCE_WEIGHTS: dict[str, dict[str, Any]] = {
        # Tool: {field_to_check, min_meaningful_value, threshold_for_confirmed}
        "fs_partition_scan": {"field": "partition_count", "min_meaningful": 0, "confirmed_at": 1},
        "fs_list_files": {"field": "file_count", "min_meaningful": 0, "confirmed_at": 2},
        "verify_hash": {
            "field": "hash",
            "min_meaningful": 1,
            "confirmed_at": 1,
        },  # Any hash is meaningful
        "list_evidence": {"field": "file_count", "min_meaningful": 0, "confirmed_at": 1},
        "fs_filesystem_info": {"field": "fsstat_output", "min_meaningful": 10, "confirmed_at": 50},
        "fs_extract_file": {
            "field": "size",
            "min_meaningful": 0,
            "confirmed_at": 1,
        },  # Any extracted data
        "carve_files": {"field": "carved_files", "min_meaningful": 0, "confirmed_at": 1},
        "scan_yara": {
            "field": "match_count",
            "min_meaningful": 1,
            "confirmed_at": 1,
        },  # Matches are always notable
        "mem_list_processes": {"field": "data", "min_meaningful": 1, "confirmed_at": 2},
        "mem_scan_network": {"field": "data", "min_meaningful": 1, "confirmed_at": 2},
        "mem_dump_cmdline": {"field": "data", "min_meaningful": 1, "confirmed_at": 2},
        "mem_analyze": {"field": "data", "min_meaningful": 1, "confirmed_at": 2},
        "reg_analyze_hive": {"field": "key_count", "min_meaningful": 0, "confirmed_at": 3},
        "pcap_analyze": {"field": "packet_count", "min_meaningful": 0, "confirmed_at": 2},
        "pcap_list_protocols": {"field": "protocols", "min_meaningful": 1, "confirmed_at": 3},
        "timeline_build": {"field": "storage_path", "min_meaningful": 1, "confirmed_at": 1},
        "timeline_filter": {"field": "event_count", "min_meaningful": 1, "confirmed_at": 5},
        "extract_features": {"field": "feature_files", "min_meaningful": 0, "confirmed_at": 1},
        "get_audit_logs": {"field": "total_entries", "min_meaningful": 1, "confirmed_at": 1},
    }

    def _assess_confidence(self, tool_name: str, result: dict[str, Any]) -> str:
        """Assess finding confidence based on data quality and tool reliability.

        CONFIRMED: Tool returned meaningful, verifiable data.
        INFERRED: Tool returned data but it's indirect or minimal.
        UNVERIFIED: Tool returned success but no meaningful data (or fallback mode).
        """
        if not result.get("success"):
            return "UNVERIFIED"

        weights = self._CONFIDENCE_WEIGHTS.get(tool_name, {})
        if not weights:
            return "INFERRED"

        field = weights["field"]
        raw_value = result.get(field)

        # Get the "value" to score
        value: int = 0
        if field == "data":
            value = (
                len(raw_value) if isinstance(raw_value, (list, dict)) else (1 if raw_value else 0)
            )
        elif field in ("fsstat_output", "protocols", "storage_path"):
            value = len(str(raw_value)) if raw_value else 0
        else:
            value = (
                int(raw_value) if isinstance(raw_value, (int, float)) else (1 if raw_value else 0)
            )

        min_val = weights["min_meaningful"]
        confirmed_at = weights["confirmed_at"]

        if value >= confirmed_at:
            return "CONFIRMED"
        elif value >= min_val:
            return "INFERRED"
        else:
            return "UNVERIFIED"

    def _extract_findings(self, tool_name: str, result: dict[str, Any]) -> None:
        """Extract structured findings from tool output with proper confidence scoring."""
        mapping: dict[str, tuple[str, Any]] = {
            "fs_partition_scan": (
                "partition_table",
                lambda r: f"Found {r.get('partition_count', 0)} partitions",
            ),
            "fs_list_files": (
                "file_listing",
                lambda r: f"Listed {r.get('file_count', 0)} files/directories",
            ),
            "verify_hash": (
                "integrity_check",
                lambda r: f"Hash ({r.get('algorithm')}): {str(r.get('hash', ''))[:20]}...",
            ),
            "list_evidence": (
                "evidence_inventory",
                lambda r: f"Found {r.get('file_count', 0)} evidence files",
            ),
            "fs_filesystem_info": ("filesystem_info", lambda r: "Filesystem analysis complete"),
            "fs_extract_file": (
                "file_extracted",
                lambda r: f"Extracted inode content ({r.get('size', 0)} bytes)",
            ),
            "carve_files": (
                "carving",
                lambda r: f"Carved {r.get('carved_files', r.get('file_count', 0))} files",
            ),
            "scan_yara": ("yara_scan", lambda r: f"Found {r.get('match_count', 0)} YARA matches"),
            "mem_list_processes": (
                "process_list",
                lambda r: f"Found {len(r.get('data', []))} processes in memory",
            ),
            "mem_scan_network": (
                "network_connections",
                lambda r: f"Found {len(r.get('data', []))} network connections",
            ),
            "mem_dump_cmdline": (
                "cmdline",
                lambda r: f"Found {len(r.get('data', []))} command lines",
            ),
            "mem_analyze": (
                "memory_analysis",
                lambda r: f"Memory analysis: {r.get('plugin', 'unknown')} plugin",
            ),
            "reg_analyze_hive": (
                "registry_analysis",
                lambda r: f"Queried registry, found {r.get('key_count', 0)} keys",
            ),
            "pcap_analyze": (
                "network_traffic",
                lambda r: f"Analyzed {r.get('packet_count', 0)} packets",
            ),
            "pcap_list_protocols": ("pcap_protocols", lambda r: "Extracted protocol hierarchy"),
            "timeline_build": (
                "timeline",
                lambda r: f"Timeline built: {r.get('storage_path', 'N/A')}",
            ),
            "timeline_filter": (
                "timeline_events",
                lambda r: f"Found {r.get('event_count', 0)} timeline events",
            ),
            "extract_features": (
                "feature_extraction",
                lambda r: f"Extracted {r.get('feature_files', 0)} feature files",
            ),
            "get_audit_logs": (
                "audit_trail",
                lambda r: f"{r.get('total_entries', 0)} tool calls logged",
            ),
        }

        if tool_name in mapping and result.get("success"):
            ftype, desc_fn = mapping[tool_name]
            desc = desc_fn(result)
            confidence = self._assess_confidence(tool_name, result)
            self.state.add_finding(
                {
                    "type": ftype,
                    "description": desc,
                    "confidence": confidence,
                    "tool": tool_name,
                    "details": result,
                }
            )

    async def _generate_report(self) -> str:
        """Generate the final report using Groq."""
        findings = self.state.findings
        tool_calls = [t.to_dict() for t in self.state.tool_calls]

        try:
            report = self.groq.generate_report(
                [f for f in findings if f.get("type") != "case_info"],
                tool_calls,
            )
            parsed = parse_report(report)
            return json.dumps(parsed, indent=2)
        except Exception as e:
            logger.warning(f"Groq report generation failed: {e}")
            return self._generate_narrative()

    def _generate_narrative(self) -> str:
        """Generate a human-readable investigation narrative (fallback)."""
        lines = ["# DFIR Investigation Report\n"]
        lines.append(f"**Status:** {self.state.status}")
        lines.append(f"**Duration:** {self.state.get_summary()['elapsed_seconds']}s")
        lines.append(f"**Tools Used:** {len(self.state.tool_calls)} calls\n")

        if self.state.findings:
            lines.append("## Key Findings\n")
            for f in self.state.findings:
                lines.append(
                    f"- **{f.get('type', 'finding')}** [{f.get('confidence', 'N/A')}]: {f.get('description', '')}"
                )

        failed = [t for t in self.state.tool_calls if not t.success]
        if failed:
            lines.append(f"\n## Errors ({len(failed)})\n")
            for t in failed[:10]:
                lines.append(f"- `{t.tool}` failed: {t.error}")

        return "\n".join(lines)

    def _build_result(self, report: str) -> dict[str, Any]:
        return {
            "success": self.state.status in ("running", "completed"),
            "status": self.state.status,
            "summary": self.state.get_summary(),
            "findings": self.state.findings,
            "tool_calls": [t.to_dict() for t in self.state.tool_calls],
            "report": report,
        }


class SimpleMCPClient:
    """Minimal MCP client for testing the agent loop against the MCP server."""

    def __init__(self, server_module: str = "src.server") -> None:
        self.server_module = server_module
        self.proc: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> bytes:
        """Start the MCP server as a subprocess."""
        import sys

        self.proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            self.server_module,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        init = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "findevil-agent", "version": "1.0"},
                    },
                }
            )
            + "\n"
        )
        self.proc.stdin.write(init.encode())  # type: ignore[union-attr]
        await self.proc.stdin.drain()  # type: ignore[union-attr]
        line: bytes = await asyncio.wait_for(self.proc.stdout.readline(), timeout=10)  # type: ignore[union-attr]
        return line

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call an MCP tool and return the parsed result."""
        msg = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            )
            + "\n"
        )
        self.proc.stdin.write(msg.encode())  # type: ignore[union-attr]
        await self.proc.stdin.drain()  # type: ignore[union-attr]

        try:
            line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=120)  # type: ignore[union-attr]
        except asyncio.TimeoutError:
            return {"success": False, "error": f"Tool {name} timed out (120s)"}

        if not line or not line.strip():
            return {"success": False, "error": f"Empty response from tool {name}"}

        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            # Try reading stderr for error info
            try:
                stderr_output = await asyncio.wait_for(self.proc.stderr.readline(), timeout=2)  # type: ignore[union-attr]
                error_detail = (
                    stderr_output.decode()
                    if isinstance(stderr_output, bytes)
                    else str(stderr_output)
                )
            except Exception:
                error_detail = ""
            return {
                "success": False,
                "error": f"Invalid JSON response from server: {line[:200]}",
                "raw": line[:500],
                "stderr": error_detail[:500],
            }

        if "result" in resp:
            content = resp["result"].get("content", [])
            is_error = resp["result"].get("isError", False)
            if content and len(content) > 0:
                text = content[0].get("text", "{}")
                # MCP framework returns plain text for validation errors
                if is_error or text.startswith("Input validation error"):
                    return {"success": False, "error": text[:500]}
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, dict):
                        return parsed
                    return {"success": True, "data": parsed}
                except json.JSONDecodeError:
                    return {"success": True, "raw_output": text[:5000]}
            return {"success": True}
        elif "error" in resp:
            err = resp["error"]
            return {
                "success": False,
                "error": err.get("message", str(err)),
                "code": err.get("code"),
            }
        return {"success": False, "error": "Unknown MCP response format"}

    async def list_tools(self) -> list[dict[str, Any]]:
        """List available MCP tools."""
        msg = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                }
            )
            + "\n"
        )
        self.proc.stdin.write(msg.encode())  # type: ignore[union-attr]
        await self.proc.stdin.drain()  # type: ignore[union-attr]
        line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=10)  # type: ignore[union-attr]
        resp = json.loads(line)
        return resp.get("result", {}).get("tools", [])  # type: ignore[no-any-return]

    async def stop(self) -> None:
        if self.proc:
            self.proc.kill()
            await self.proc.wait()
