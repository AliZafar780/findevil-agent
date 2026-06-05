"""
Structured output extraction from tool results.
"""

import json
import re
from typing import Optional


def _extract_balanced_braces(text: str) -> list[str]:
    """Extract top-level JSON objects with balanced braces, handling nesting."""
    results = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                candidate = text[start : i + 1]
                results.append(candidate)
                start = -1
    return results


def extract_json_from_text(text: str) -> Optional[dict]:
    """Extract JSON object from text that may contain markdown or other content."""
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find JSON in code blocks
    code_block_pattern = r"```(?:json)?\s*\n(.*?)\n```"
    try:
        matches = re.findall(code_block_pattern, text, re.DOTALL)
        for m in matches:
            try:
                return json.loads(m.strip())
            except json.JSONDecodeError:
                # Try extracting balanced braces from within the block
                for candidate in _extract_balanced_braces(m):
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass

    # Try extracting balanced braces from the full text (handles nested objects)
    for candidate in _extract_balanced_braces(text):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    return None


def parse_tool_decision(text: str) -> list:
    """Parse LLM tool decision output into a list of tool names.

    Only returns tool names when:
    1. They appear in a JSON block with "tools" or "next_tools" key (preferred)
    2. They appear in a list/bullet context suggesting to call them (fallback)
    Avoids matching tool names mentioned in prose or analysis text.
    """
    parsed = extract_json_from_text(text)
    if parsed and isinstance(parsed, dict):
        tools = parsed.get("tools", parsed.get("next_tools", []))
        if isinstance(tools, list):
            return [t.get("name", t) if isinstance(t, dict) else t for t in tools]

    # Fallback: extract tool names only from calling contexts
    tool_names = [
        "fs_partition_scan",
        "fs_list_files",
        "fs_extract_file",
        "fs_file_metadata",
        "fs_filesystem_info",
        "carve_files",
        "scan_yara",
        "verify_hash",
        "list_evidence",
        "mem_analyze",
        "mem_list_processes",
        "mem_scan_network",
        "mem_dump_cmdline",
        "reg_analyze_hive",
        "pcap_analyze",
        "pcap_list_protocols",
        "get_audit_logs",
    ]

    # Only match tool names preceded by action verbs suggesting tool invocation
    text_lower = text.lower()
    action_prefixes = [
        "run ",
        "call ",
        "execute ",
        "use ",
        "try ",
        "next: ",
        "- ",
        "* ",
        "1. ",
        "2. ",
        "3. ",
        "4. ",
        "5. ",
        "invoke ",
        "suggest",
        "recommend",
        "should run",
        "will use",
    ]

    found = []
    for tool in tool_names:
        for prefix in action_prefixes:
            if prefix + tool in text_lower:
                found.append(tool)
                break
            # Also check for line starting with tool name (list items)
            for line in text_lower.split("\n"):
                stripped = line.strip().rstrip(".")
                if stripped == tool or stripped.startswith(tool + " "):
                    found.append(tool)
                    break

    return list(set(found))


def parse_report(text: str) -> dict:
    """Parse the final report from LLM output."""
    parsed = extract_json_from_text(text)
    if parsed:
        return parsed
    return {"raw_report": text[:10000]}
