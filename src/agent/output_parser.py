"""
Structured output extraction from tool results.
"""
import json
import re
from typing import Any, Optional


def extract_json_from_text(text: str) -> Optional[dict]:
    """Extract JSON object from text that may contain markdown or other content."""
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find JSON in code blocks
    patterns = [
        r'```(?:json)?\s*\n(.*?)\n```',
        r'\{[^{}]*\}',
    ]
    for pattern in patterns:
        try:
            matches = re.findall(pattern, text, re.DOTALL)
            for m in matches:
                try:
                    return json.loads(m.strip())
                except json.JSONDecodeError:
                    continue
        except Exception:
            continue
    return None


def parse_tool_decision(text: str) -> list:
    """Parse LLM tool decision output into a list of tool names."""
    parsed = extract_json_from_text(text)
    if parsed and isinstance(parsed, dict):
        tools = parsed.get("tools", parsed.get("next_tools", []))
        if isinstance(tools, list):
            return [t.get("name", t) if isinstance(t, dict) else t for t in tools]

    # Fallback: extract tool names from text
    tool_pattern = r'\b(fs_partition_scan|fs_list_files|fs_extract_file|fs_file_metadata|fs_filesystem_info|carve_files|scan_yara|verify_hash|list_evidence|mem_analyze|mem_list_processes|mem_scan_network|mem_dump_cmdline|reg_analyze_hive|pcap_analyze|pcap_list_protocols|get_audit_logs)\b'
    return list(set(re.findall(tool_pattern, text)))


def parse_report(text: str) -> dict:
    """Parse the final report from LLM output."""
    parsed = extract_json_from_text(text)
    if parsed:
        return parsed
    return {"raw_report": text[:10000]}
