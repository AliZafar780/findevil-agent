"""
Self-Correcting DFIR Agent Loop with Groq LLM integration.
Implements the ReAct pattern: Reason → Act → Observe → Correct → Report
"""
import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .groq_client import GroqDFIRClient
from .output_parser import parse_tool_decision, parse_report
from .prompts import DFIR_ANALYST_PROMPT

logger = logging.getLogger("findevil-agent")


class ToolCall:
    """Record of a single tool execution."""
    def __init__(self, tool: str, arguments: dict, iteration: int):
        self.tool = tool
        self.arguments = arguments
        self.iteration = iteration
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.success = False
        self.result = None
        self.error = None
        self.duration_ms = 0
        self.start_time = time.time()

    def complete(self, result: Any, duration: float):
        self.result = result
        self.duration = duration
        self.duration_ms = int(duration * 1000)

    def to_dict(self) -> dict:
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

    def __init__(self, max_iterations: int = 30):
        self.iteration = 0
        self.max_iterations = max_iterations
        self.tool_calls: list[ToolCall] = []
        self.findings: list[dict] = []
        self.consecutive_failures = 0
        self.start_time = time.time()
        self.status = "running"
        self.last_tool_results = {}
        self.errors = []

    def should_abort(self) -> tuple[bool, str]:
        if self.iteration >= self.max_iterations:
            return True, f"Max iterations ({self.max_iterations}) reached"
        if self.consecutive_failures >= 5:
            return True, f"{self.consecutive_failures} consecutive tool failures"
        elapsed = time.time() - self.start_time
        if elapsed > 3600:
            return True, f"Time limit exceeded ({int(elapsed)}s)"
        return False, ""

    def record_call(self, tool_call: ToolCall):
        self.tool_calls.append(tool_call)
        if tool_call.success:
            self.consecutive_failures = 0
            self.last_tool_results[tool_call.tool] = tool_call.result
        else:
            self.consecutive_failures += 1
            self.errors.append(f"{tool_call.tool}: {tool_call.error}")

    def add_finding(self, finding: dict):
        self.findings.append(finding)

    def get_summary(self) -> dict:
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
        "initial_triage": ["list_evidence", "verify_hash", "fs_partition_scan", "fs_filesystem_info"],
        "filesystem_analysis": ["fs_list_files", "fs_file_metadata", "fs_extract_file"],
        "artifact_extraction": ["carve_files", "scan_yara"],
        "memory_analysis": ["mem_list_processes", "mem_analyze", "mem_scan_network", "mem_dump_cmdline"],
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

    async def run(self, task: str, evidence_path: str) -> dict:
        """Execute the complete DFIR workflow across all phases."""
        logger.info(f"Starting DFIR workflow: {task[:200]}" if task else "Starting DFIR workflow")
        logger.info(f"Evidence: {evidence_path[:200]}" if evidence_path else "Evidence: (none)")
        self._evidence_path = evidence_path

        self.state.add_finding({
            "type": "case_info",
            "description": f"Case initiated: {task}",
            "task": task,
            "evidence": evidence_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "confidence": "CONFIRMED",
        })

        for phase in self.PHASES:
            if self.state.status != "running":
                break
            self.current_phase = phase
            logger.info(f"━" * 60)
            logger.info(f"  PHASE: {phase}")
            logger.info(f"━" * 60)

            if phase == "reporting":
                break

            await self._execute_phase()

        # Generate final report using Groq
        report = await self._generate_report()
        return self._build_result(report)

    async def _execute_phase(self):
        """Execute a single analysis phase."""
        # Auto-detect partition offset
        if self.current_phase in ("initial_triage", "filesystem_analysis") and self._detected_offset == 0:
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
                fallbacks = self.FALLBACKS.get(tool_name, [])
                for fb in fallbacks:
                    if self.state.consecutive_failures >= 3:
                        break
                    logger.info(f"  ↪ Fallback: {fb}")
                    await self._try_fallback(fb)
                    if self.state.consecutive_failures == 0:
                        break  # Fallback worked

            self.state.record_call(tool_call)

    async def _get_phase_tools(self) -> list:
        """Get tools for current phase, using LLM when possible."""
        defaults = self.DEFAULT_TOOLS.get(self.current_phase, [])

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
                    return [t.get("name", t) if isinstance(t, dict) else t for t in llm_decision]
            except Exception as e:
                logger.warning(f"LLM tool selection failed: {e}")

        return defaults

    async def _detect_partition_offset(self) -> int:
        """Auto-detect the data partition offset from a disk image."""
        try:
            result = await self.client.call_tool("fs_partition_scan", {"image_path": self._evidence_path})
            if isinstance(result, str):
                parsed = json.loads(result)
            else:
                parsed = result

            if parsed.get("success"):
                partitions = parsed.get("partitions", [])
                excluded_descs = {"safety table", "gpt header", "partition table", "unallocated", "meta"}
                for p in partitions:
                    desc = p.get("description", "").strip().lower()
                    length = p.get("length", 0)
                    slot = p.get("slot", -1)
                    if slot >= 0 and desc not in excluded_descs and length > 100:
                        logger.info(f"Auto-detected partition offset: {p.get('start', 0)} (slot {slot})")
                        return p.get("start", 0)
            return 0
        except Exception as e:
            logger.warning(f"Failed to detect partition offset: {e}")
            return 0

    def _build_args(self, tool_name: str) -> dict:
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
            "carve_files": {"image_path": ep, "file_types": "all", "output_dir": "/results/carved/agent"},
            "scan_yara": {"target": ep, "rules": "rule FindEvil { strings: $a = \"malware\" nocase condition: $a }"},
            "mem_analyze": {"memory_path": ep, "plugin": "windows.pslist.PsList"},
            "mem_list_processes": {"memory_path": ep},
            "mem_scan_network": {"memory_path": ep},
            "mem_dump_cmdline": {"memory_path": ep},
            "reg_analyze_hive": {"hive_path": ep, "key": "/Microsoft/Windows/CurrentVersion/Run"},
            "pcap_analyze": {"pcap_path": ep, "max_packets": 100},
            "pcap_list_protocols": {"pcap_path": ep},
            "get_audit_logs": {"limit": 50},
        }
        return arg_map.get(tool_name, {})

    async def _try_fallback(self, tool_name: str):
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

    def _extract_findings(self, tool_name: str, result: dict):
        """Extract structured findings from tool output."""
        mapping = {
            "fs_partition_scan": ("partition_table", f"Found {result.get('partition_count', 0)} partitions"),
            "fs_list_files": ("file_listing", f"Listed {result.get('file_count', 0)} files/directories"),
            "verify_hash": ("integrity_check", f"Hash ({result.get('algorithm')}): {str(result.get('hash', ''))[:20]}..."),
            "list_evidence": ("evidence_inventory", f"Found {result.get('file_count', 0)} evidence files"),
            "fs_filesystem_info": ("filesystem_info", f"Filesystem analysis complete"),
            "fs_extract_file": ("file_extracted", f"Extracted inode content ({result.get('size', 0)} bytes)"),
            "carve_files": ("carving", f"Carved {result.get('file_count', 0)} files"),
            "scan_yara": ("yara_scan", f"Found {result.get('match_count', 0)} YARA matches"),
            "mem_list_processes": ("process_list", f"Found {len(result.get('data', []))} processes in memory"),
            "mem_scan_network": ("network_connections", f"Found {len(result.get('data', []))} network connections"),
            "reg_analyze_hive": ("registry_analysis", f"Queried registry, found {result.get('key_count', 0)} keys"),
            "pcap_analyze": ("network_traffic", f"Analyzed {result.get('packet_count', 0)} packets"),
            "pcap_list_protocols": ("pcap_protocols", "Extracted protocol hierarchy"),
            "get_audit_logs": ("audit_trail", f"{result.get('total_entries', 0)} tool calls logged"),
        }

        if tool_name in mapping and result.get("success"):
            ftype, desc = mapping[tool_name]
            self.state.add_finding({
                "type": ftype,
                "description": desc,
                "confidence": "CONFIRMED" if result.get("success") else "UNVERIFIED",
                "tool": tool_name,
                "details": result,
            })

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
                lines.append(f"- **{f.get('type', 'finding')}** [{f.get('confidence', 'N/A')}]: {f.get('description', '')}")

        failed = [t for t in self.state.tool_calls if not t.success]
        if failed:
            lines.append(f"\n## Errors ({len(failed)})\n")
            for t in failed[:10]:
                lines.append(f"- `{t.tool}` failed: {t.error}")

        return "\n".join(lines)

    def _build_result(self, report: str) -> dict:
        return {
            "success": self.state.status == "running",
            "status": self.state.status,
            "summary": self.state.get_summary(),
            "findings": self.state.findings,
            "tool_calls": [t.to_dict() for t in self.state.tool_calls],
            "report": report,
        }


class SimpleMCPClient:
    """Minimal MCP client for testing the agent loop against the MCP server."""

    def __init__(self, server_module: str = "src.server"):
        self.server_module = server_module
        self.proc = None

    async def start(self):
        """Start the MCP server as a subprocess."""
        import sys
        self.proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", self.server_module,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        init = json.dumps({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "findevil-agent", "version": "1.0"},
            }
        }) + "\n"
        self.proc.stdin.write(init.encode())
        await self.proc.stdin.drain()
        line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=10)
        return line

    async def call_tool(self, name: str, arguments: dict) -> dict:
        """Call an MCP tool and return the parsed result."""
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }) + "\n"
        self.proc.stdin.write(msg.encode())
        await self.proc.stdin.drain()

        try:
            line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=120)
        except asyncio.TimeoutError:
            return {"success": False, "error": f"Tool {name} timed out (120s)"}

        if not line or not line.strip():
            return {"success": False, "error": f"Empty response from tool {name}"}

        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            # Try reading stderr for error info
            try:
                stderr_output = await asyncio.wait_for(self.proc.stderr.readline(), timeout=2)
                error_detail = stderr_output.decode() if isinstance(stderr_output, bytes) else str(stderr_output)
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

    async def list_tools(self) -> list:
        """List available MCP tools."""
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list",
            "params": {},
        }) + "\n"
        self.proc.stdin.write(msg.encode())
        await self.proc.stdin.drain()
        line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=10)
        resp = json.loads(line)
        return resp.get("result", {}).get("tools", [])

    async def stop(self):
        if self.proc:
            self.proc.kill()
            await self.proc.wait()
