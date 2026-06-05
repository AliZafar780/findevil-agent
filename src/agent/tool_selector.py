"""
Intelligent tool selection for DFIR analysis.
Helps the agent choose the right tool for each situation.
"""

from typing import Any, Optional

TOOL_REGISTRY = {
    "initial_triage": [
        {
            "tool": "fs_partition_scan",
            "description": "Scan partition table — always start here for disk images",
            "priority": 1,
        },
        {
            "tool": "verify_hash",
            "description": "Verify evidence integrity with SHA256",
            "priority": 2,
        },
    ],
    "filesystem_analysis": [
        {
            "tool": "fs_list_files",
            "description": "List files in a directory by path or inode",
            "priority": 1,
        },
        {
            "tool": "fs_extract_file",
            "description": "Extract file content by inode number",
            "priority": 2,
        },
        {
            "tool": "fs_filesystem_info",
            "description": "Get file system metadata via fsstat",
            "priority": 3,
        },
    ],
    "memory_analysis": [
        {
            "tool": "mem_list_processes",
            "description": "List running processes from memory",
            "priority": 1,
        },
        {
            "tool": "mem_analyze",
            "description": "Run Volatility plugins (pslist, netscan, cmdline, malfind)",
            "priority": 2,
        },
        {
            "tool": "mem_dump_cmdline",
            "description": "Extract command lines from memory processes",
            "priority": 3,
        },
    ],
    "timeline_analysis": [
        {
            "tool": "timeline_build",
            "description": "Build comprehensive timeline with Plaso",
            "priority": 1,
        },
        {
            "tool": "timeline_filter",
            "description": "Filter timeline by date range or event type",
            "priority": 2,
        },
        {
            "tool": "extract_features",
            "description": "Extract emails, URLs, credentials as timeline supplements",
            "priority": 3,
        },
    ],
    "artifact_extraction": [
        {
            "tool": "carve_files",
            "description": "Carve deleted files by type",
            "priority": 1,
        },
        {
            "tool": "extract_features",
            "description": "Extract emails, URLs, credentials with bulk_extractor",
            "priority": 2,
        },
        {
            "tool": "scan_yara",
            "description": "Scan with YARA rules for malware",
            "priority": 3,
        },
    ],
}


def suggest_next_tools(
    phase: str, previous_results: Optional[dict[str, Any]] = None
) -> list[dict[str, Any]]:
    """Suggest appropriate tools based on analysis phase."""
    tools = TOOL_REGISTRY.get(phase, [])
    return sorted(tools, key=lambda t: t["priority"])


def get_tool_for_artifact(artifact_type: str) -> str:
    """Get the best tool for analyzing a specific artifact type."""
    artifact_tools = {
        # Disk/FS findings
        "partition_table": "fs_partition_scan",
        "file_listing": "fs_list_files",
        "integrity_check": "verify_hash",
        "evidence_inventory": "list_evidence",
        # Memory findings
        "process_list": "mem_list_processes",
        "network_connections": "mem_scan_network",
        "command_line": "mem_dump_cmdline",
        # Registry findings
        "registry_key": "reg_analyze_hive",
        "registry_analysis": "reg_analyze_hive",
        # Network findings
        "pcap_protocols": "pcap_list_protocols",
        "network_traffic": "pcap_analyze",
        # Extraction findings
        "file_content": "fs_extract_file",
        "carving": "carve_files",
        "yara_match": "scan_yara",
        # Audit
        "audit_trail": "get_audit_logs",
    }
    return artifact_tools.get(artifact_type, "fs_partition_scan")


def get_fallback_chain(tool: str) -> list[str]:
    """Get alternative tools when the primary tool fails."""
    fallbacks = {
        "fs_list_files": ["carve_files"],
        "fs_extract_file": ["carve_files", "scan_yara"],
        "fs_partition_scan": ["fs_filesystem_info", "list_evidence"],
        "scan_yara": ["carve_files", "extract_features", "verify_hash"],
        "mem_list_processes": ["mem_analyze", "mem_dump_cmdline"],
        "mem_analyze": ["mem_list_processes", "mem_dump_cmdline"],
        "mem_scan_network": ["mem_analyze"],
        "mem_dump_cmdline": ["mem_analyze"],
        "pcap_analyze": ["pcap_list_protocols"],
        "reg_analyze_hive": ["fs_list_files", "scan_yara"],
        "timeline_build": ["extract_features"],
        "carve_files": ["extract_features"],
    }
    return fallbacks.get(tool, ["fs_list_files", "verify_hash"])
