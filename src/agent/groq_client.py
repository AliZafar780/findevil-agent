"""
Groq LLM Client for the FindEvil agent.
Provides structured reasoning, tool selection, and self-correction.
"""
import json
import logging
import os
from typing import Optional

from groq import Groq

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


class GroqDFIRClient:
    """Groq-powered LLM client for DFIR analysis with self-correction."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Groq API key required. Set GROQ_API_KEY env var or pass api_key."
            )
        self.client = Groq(api_key=self.api_key)
        self.model = model or DEFAULT_MODEL
        self.conversation_history = []
        self.system_prompt = SYSTEM_PROMPT_DFIR

    def reset_conversation(self):
        """Reset the conversation history for a new case."""
        self.conversation_history = []

    def _call_groq(self, messages: list, temperature: float = 0.1) -> str:
        """Make a call to Groq with fallback models."""
        models_to_try = [self.model] + [m for m in FALLBACK_MODELS if m != self.model]

        for model in models_to_try:
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=4096,
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                logger.warning(f"Model {model} failed: {e}")
                continue

        raise RuntimeError("All Groq models failed. Check API key and quota.")

    def analyze_findings(self, tool_results: list, task: str) -> str:
        """Have the LLM analyze tool results and provide reasoning."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Task: {task}\n\nTool results to analyze:\n{json.dumps(tool_results, indent=2)[:15000]}\n\nAnalyze these findings and determine next steps. What tools should be called next?"},
        ]
        return self._call_groq(messages)

    def decide_next_tools(self, phase: str, last_results: dict, errors: list) -> list:
        """Have the LLM decide which tools to run next based on results."""
        results_summary = json.dumps(last_results, indent=2)[:8000]
        errors_summary = "; ".join(errors[:5]) if errors else "None"

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"""Current phase: {phase}

Last tool results: {results_summary}

Errors encountered: {errors_summary}

Based on these results, which tools should I run next? 
Return a JSON list of tool names with brief reasoning for each.
Available tools: fs_partition_scan, fs_list_files, fs_extract_file, fs_file_metadata, fs_filesystem_info, carve_files, scan_yara, verify_hash, list_evidence, mem_analyze, mem_list_processes, mem_scan_network, mem_dump_cmdline, reg_analyze_hive, pcap_analyze, pcap_list_protocols, get_audit_logs

Format: {{"tools": [{{"name": "tool_name", "reasoning": "why this tool"}}]}}"""},
        ]
        result = self._call_groq(messages)
        try:
            parsed = json.loads(result)
            return parsed.get("tools", [])
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse LLM tool decision: {result[:200]}")
            return []

    def generate_report(self, all_findings: list, tool_calls: list) -> str:
        """Generate a final structured report from all findings.
        Returns pure JSON (extracts from markdown if needed)."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"""Generate a final DFIR investigation report based on these findings and tool calls.

Findings: {json.dumps(all_findings, indent=2)[:10000]}
Tool calls: {json.dumps(tool_calls, indent=2)[:5000]}

Output ONLY valid JSON with NO markdown formatting, NO code blocks.
Use this exact structure:
{{
  "summary": "Brief investigation summary",
  "findings": [list of finding objects with type, description, confidence, tool, evidence fields],
  "timeline": [list of events with timestamp, event, artifact],
  "open_questions": [list of questions],
  "recommendations": [list of recommendations]
}}"""},
        ]
        result = self._call_groq(messages)
        # Try direct parse first, then extract from markdown
        try:
            json.loads(result)
            return result
        except json.JSONDecodeError:
            pass
        # Try extraction from markdown
        from .output_parser import extract_json_from_text
        parsed = extract_json_from_text(result)
        if parsed:
            return json.dumps(parsed, indent=2)
        # Last resort: return as-is
        return result

    def self_correct(self, error: str, failed_tool: str, context: dict) -> str:
        """Have the LLM suggest recovery from a tool failure."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"""Tool failure detected!

Failed tool: {failed_tool}
Error: {error}
Context: {json.dumps(context, indent=2)[:5000]}

What alternative approach should I try? Suggest specific tools and parameters."""},
        ]
        return self._call_groq(messages, temperature=0.3)

    def generate_demo_report(self, tool_results: list) -> dict:
        """Generate a complete submission-ready demo report."""
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"""Here are the forensic analysis results from investigating a disk image:

{json.dumps(tool_results, indent=2)[:20000]}

Generate a complete DFIR investigation report as JSON with:
1. Executive summary
2. Key findings with confidence levels
3. Timeline of events
4. Artifacts of interest
5. Open questions
6. Recommendations"""},
        ]
        result = self._call_groq(messages, temperature=0.2)
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"report": result}
