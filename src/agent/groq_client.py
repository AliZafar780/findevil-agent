"""
Groq LLM Client for the FindEvil agent.
Provides structured reasoning, tool selection, and self-correction.

The client is OPTIONAL — if no GROQ_API_KEY is set, the agent runs in
deterministic mode using static tool chains and a simple narrative report generator.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from src.agent.output_parser import extract_json_from_text

logger = logging.getLogger("findevil-groq")

# Default Groq model (fast + capable)
DEFAULT_MODEL = "llama-3.3-70b-versatile"
# Fallback models if primary is unavailable
FALLBACK_MODELS = ["llama3-70b-8192", "mixtral-8x7b-32768", "gemma2-9b-it"]

SYSTEM_PROMPT_DFIR = """You are a Senior DFIR (Digital Forensics & Incident Response) Analyst with 20 years of experience. You have analyzed thousands of compromised systems.

## YOUR ROLE
You are examining digital evidence to determine what happened, when, and by whom.

## CORE PRINCIPLES
1. **EVIDENCE INTEGRITY**: Never modify original evidence. Read-only operations only.
2. **METHODICAL**: Start broad (partition scan), then deep (file analysis, memory, network).
3. **SELF-CORRECT**: If a tool returns an error, try an alternative approach. Document failures.
4. **HALLUCINATION PREVENTION**:
   - Clearly label findings as CONFIRMED, INFERRED, or UNVERIFIED
   - Never fabricate tool output
   - If output is empty, say so
5. **TRACEABILITY**: Every finding must reference the specific tool and parameters that produced it.

## AVAILABLE TOOLS
You have access to these forensic tools through an MCP server:
- fs_partition_scan: Scan partition table (mmls)
- fs_list_files: List files in image (fls)
- fs_extract_file: Extract file by inode (icat)
- fs_file_metadata: Get file metadata (istat)
- fs_filesystem_info: Get FS statistics (fsstat)
- carve_files: Carve deleted files (foremost)
- scan_yara: Scan with YARA rules
- verify_hash: Compute file hash
- list_evidence: List available evidence
- mem_analyze: Run volatility plugin
- mem_list_processes: List processes from memory
- mem_scan_network: Network connections from memory
- mem_dump_cmdline: Dump process command lines
- reg_analyze_hive: Query registry hive
- pcap_analyze: Analyze PCAP file
- pcap_list_protocols: List protocols in PCAP
- get_audit_logs: Get execution logs

## STANDARD WORKFLOW
1. Triage: partition scan → hash → evidence listing
2. Filesystem: FS info → list files → extract interesting files
3. Deep analysis: memory/registry/network as applicable
4. Cross-reference: validate findings across tools
5. Report: structured findings with confidence levels

## REPORTING FORMAT
When you have all findings, output a JSON report with:
{
  "summary": "Brief investigation summary",
  "findings": [
    {
      "type": "finding_type",
      "description": "What was found",
      "confidence": "CONFIRMED|INFERRED|UNVERIFIED",
      "tool": "tool_name",
      "evidence": "specific evidence from tool output"
    }
  ],
  "timeline": [{"timestamp": "...", "event": "...", "artifact": "..."}],
  "open_questions": ["..."],
  "recommendations": ["..."]
}
"""

# Token & cost tracking defaults
MAX_TOKENS_PER_CALL = 4096
MAX_TOTAL_TOKENS_PER_SESSION = 100_000
COST_PER_1K_INPUT_TOKENS = 0.00059  # Llama 3.3 70B approx
COST_PER_1K_OUTPUT_TOKENS = 0.00079


class GroqDFIRClient:
    """Groq-powered LLM client for DFIR analysis with self-correction and token tracking.

    If GROQ_API_KEY is not set, the client operates in UNAVAILABLE mode:
    all methods return empty/fallback values and the agent uses deterministic
    tool chains and a built-in report generator instead.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self.available = bool(self.api_key)
        self.model = model or DEFAULT_MODEL
        self.conversation_history = []
        self.system_prompt = SYSTEM_PROMPT_DFIR

        # Token and cost tracking
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.total_cost = 0.0
        self.api_calls = 0
        self.max_total_tokens = int(
            os.environ.get("GROQ_MAX_TOKENS", str(MAX_TOTAL_TOKENS_PER_SESSION))
        )

        if self.available:
            try:
                from groq import Groq as GroqClient

                self.client = GroqClient(api_key=self.api_key)
                logger.info("Groq client initialized (model: %s)", self.model)
            except Exception as e:
                logger.warning("Failed to initialize Groq client: %s", e)
                self.available = False

        if not self.available:
            logger.info(
                "Groq client not available — running in deterministic mode. "
                "Set GROQ_API_KEY for LLM-powered analysis."
            )

    def reset_conversation(self):
        """Reset the conversation history for a new case."""
        self.conversation_history = []
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.total_cost = 0.0
        self.api_calls = 0

    def get_usage_summary(self) -> dict:
        """Return current token and cost usage summary."""
        return {
            "available": self.available,
            "api_calls": self.api_calls,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost, 6),
            "model": self.model or "none (deterministic mode)",
        }

    def _check_token_budget(self, estimated_tokens: int = 4096) -> bool:
        """Check if adding estimated_tokens would exceed the session budget."""
        if self.total_tokens + estimated_tokens > self.max_total_tokens:
            logger.warning(
                "Token budget exceeded: %s + %s > %s",
                self.total_tokens,
                estimated_tokens,
                self.max_total_tokens,
            )
            return False
        return True

    def _call_groq(self, messages: list, temperature: float = 0.1) -> str:
        """Make a call to Groq with fallback models and token tracking.

        Returns empty string if client is unavailable or all models fail.
        """
        if not self.available:
            return ""

        if not self._check_token_budget():
            return ""

        models_to_try = [self.model] + [m for m in FALLBACK_MODELS if m != self.model]

        for model in models_to_try:
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=MAX_TOKENS_PER_CALL,
                )

                if hasattr(response, "usage") and response.usage:
                    usage = response.usage
                    self.total_prompt_tokens += usage.prompt_tokens or 0
                    self.total_completion_tokens += usage.completion_tokens or 0
                    self.total_tokens += usage.total_tokens or 0
                    self.total_cost += (
                        (usage.prompt_tokens or 0) / 1000
                    ) * COST_PER_1K_INPUT_TOKENS + (
                        (usage.completion_tokens or 0) / 1000
                    ) * COST_PER_1K_OUTPUT_TOKENS
                self.api_calls += 1

                logger.debug(
                    "Groq call (%s): tokens=%s, cost=$%.6f, calls=%s",
                    model,
                    self.total_tokens,
                    self.total_cost,
                    self.api_calls,
                )
                return response.choices[0].message.content or ""

            except Exception as e:
                logger.warning("Model %s failed: %s", model, e)
                continue

        logger.error("All Groq models failed. Check API key and quota.")
        return ""

    def analyze_findings(self, tool_results: list, task: str) -> str:
        """Have the LLM analyze tool results and provide reasoning."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {
                "role": "user",
                "content": (
                    f"Task: {task}\n\nTool results to analyze:\n"
                    f"{json.dumps(tool_results, indent=2)[:15000]}\n\n"
                    f"Analyze these findings and determine next steps. What tools should be called next?"
                ),
            },
        ]
        return self._call_groq(messages)

    def decide_next_tools(self, phase: str, last_results: dict, errors: list) -> list:
        """Have the LLM decide which tools to run next based on results.

        Returns empty list if client is unavailable — caller should fall back
        to deterministic tool chains.
        """
        if not self.available:
            return []

        results_summary = json.dumps(last_results, indent=2)[:8000]
        errors_summary = "; ".join(errors[:5]) if errors else "None"

        messages = [
            {"role": "system", "content": self.system_prompt},
            {
                "role": "user",
                "content": (
                    f"Current phase: {phase}\n\n"
                    f"Last tool results: {results_summary}\n\n"
                    f"Errors encountered: {errors_summary}\n\n"
                    f"Based on these results, which tools should I run next? \n"
                    f"Return a JSON list of tool names with brief reasoning for each.\n"
                    f"Output ONLY valid JSON with NO markdown formatting, NO code blocks.\n"
                    f"Available tools: fs_partition_scan, fs_list_files, fs_extract_file, "
                    f"fs_file_metadata, fs_filesystem_info, carve_files, scan_yara, "
                    f"verify_hash, list_evidence, mem_analyze, mem_list_processes, "
                    f"mem_scan_network, mem_dump_cmdline, reg_analyze_hive, pcap_analyze, "
                    f"pcap_list_protocols, get_audit_logs\n\n"
                    f'Format: {{"tools": [{{"name": "tool_name", "reasoning": "why this tool"}}]}}'
                ),
            },
        ]
        result = self._call_groq(messages)
        if not result:
            return []
        try:
            parsed = extract_json_from_text(result)
            if parsed and isinstance(parsed, dict):
                tools = parsed.get("tools", parsed.get("next_tools", []))
                if isinstance(tools, list):
                    return [t.get("name", t) if isinstance(t, dict) else t for t in tools]
            # Also try direct parse as fallback
            parsed = json.loads(result)
            return parsed.get("tools", [])
        except (json.JSONDecodeError, TypeError, AttributeError):
            logger.warning("Failed to parse LLM tool decision: %s", result[:200])
            return []

    def generate_report(self, all_findings: list, tool_calls: list) -> str:
        """Generate a final structured report from all findings.

        Returns JSON string. Falls back to narrative report if LLM unavailable.
        """
        if not self.available:
            return _generate_narrative_report(all_findings, tool_calls)

        messages = [
            {"role": "system", "content": self.system_prompt},
            {
                "role": "user",
                "content": (
                    f"Generate a final DFIR investigation report based on these findings and tool calls.\n\n"
                    f"Findings: {json.dumps(all_findings, indent=2)[:10000]}\n"
                    f"Tool calls: {json.dumps(tool_calls, indent=2)[:5000]}\n\n"
                    f"Output ONLY valid JSON with NO markdown formatting, NO code blocks.\n"
                    f"Use this exact structure:\n"
                    f"{{\n"
                    f'  "summary": "Brief investigation summary",\n'
                    f'  "findings": [list of finding objects with type, description, confidence, tool, evidence fields],\n'
                    f'  "timeline": [list of events with timestamp, event, artifact],\n'
                    f'  "open_questions": [list of questions],\n'
                    f'  "recommendations": [list of recommendations]\n'
                    f"}}"
                ),
            },
        ]
        result = self._call_groq(messages)
        if not result:
            return _generate_narrative_report(all_findings, tool_calls)

        try:
            json.loads(result)
            return result
        except json.JSONDecodeError:
            pass

        from .output_parser import extract_json_from_text

        parsed = extract_json_from_text(result)
        if parsed:
            return json.dumps(parsed, indent=2)

        return _generate_narrative_report(all_findings, tool_calls)

    def self_correct(self, error: str, failed_tool: str, context: dict) -> str:
        """Have the LLM suggest recovery from a tool failure.

        Returns empty string if unavailable.
        """
        if not self.available:
            return ""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {
                "role": "user",
                "content": (
                    f"Tool failure detected!\n\n"
                    f"Failed tool: {failed_tool}\n"
                    f"Error: {error}\n"
                    f"Context: {json.dumps(context, indent=2)[:5000]}\n\n"
                    f"What alternative approach should I try? Suggest specific tools and parameters."
                ),
            },
        ]
        return self._call_groq(messages, temperature=0.3)

    def generate_demo_report(self, tool_results: list) -> dict:
        """Generate a complete submission-ready demo report."""
        if not self.available:
            return {"report": _generate_narrative_report([], [])}
        messages = [
            {"role": "system", "content": self.system_prompt},
            {
                "role": "user",
                "content": (
                    f"Here are the forensic analysis results from investigating a disk image:\n\n"
                    f"{json.dumps(tool_results, indent=2)[:20000]}\n\n"
                    f"Generate a complete DFIR investigation report as JSON with:\n"
                    f"1. Executive summary\n"
                    f"2. Key findings with confidence levels\n"
                    f"3. Timeline of events\n"
                    f"4. Artifacts of interest\n"
                    f"5. Open questions\n"
                    f"6. Recommendations"
                ),
            },
        ]
        result = self._call_groq(messages, temperature=0.2)
        if not result:
            return {"report": _generate_narrative_report([], [])}
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"report": result}


def _generate_narrative_report(all_findings: list, tool_calls: list) -> str:
    """Generate a human-readable investigation narrative (no LLM needed).

    This is the fallback report generator used when Groq is unavailable.
    """
    lines = []
    lines.append("# DFIR Investigation Report")
    lines.append("---")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append("**Mode:** Deterministic (no LLM)")
    lines.append("")

    successful = sum(1 for t in tool_calls if isinstance(t, dict) and t.get("success"))
    failed = sum(1 for t in tool_calls if isinstance(t, dict) and not t.get("success"))

    lines.append("## Summary")
    lines.append(f"- **Tools called:** {len(tool_calls)}")
    lines.append(f"- **Successful:** {successful}")
    lines.append(f"- **Failed:** {failed}")
    lines.append(f"- **Findings:** {len(all_findings)}")
    lines.append("")

    if all_findings:
        lines.append("## Key Findings")
        lines.append("")
        for f in all_findings:
            ftype = f.get("type", "finding") if isinstance(f, dict) else "finding"
            fdesc = f.get("description", "") if isinstance(f, dict) else str(f)
            fconf = f.get("confidence", "UNVERIFIED") if isinstance(f, dict) else "UNVERIFIED"
            lines.append(f"### {ftype} [{fconf}]")
            lines.append(f"{fdesc}")
            lines.append("")

    if failed:
        lines.append("## Issues Encountered")
        lines.append("")
        for t in tool_calls:
            if isinstance(t, dict) and not t.get("success"):
                lines.append(
                    f"- `{t.get('tool', 'unknown')}` failed: {t.get('error', 'unknown error')}"
                )
        lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    if successful > 0:
        lines.append(
            "- Review findings from successful tool executions for indicators of compromise."
        )
    if failed > 0:
        lines.append(
            "- Investigate tool failures — they may indicate corrupted evidence or missing dependencies."
        )
    lines.append("- For deeper analysis, consider running additional tools on specific artifacts.")
    lines.append("")

    return "\n".join(lines)
