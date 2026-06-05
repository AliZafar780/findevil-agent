"""Tests for the Groq LLM client module (unit tests, no live API calls)."""
import sys
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestGroqClientUnit:
    """Unit tests for GroqDFIRClient (no live API)."""

    def test_groq_client_requires_api_key(self):
        """Client handles missing API key gracefully (deterministic mode)."""
        import os
        from src.agent.groq_client import GroqDFIRClient

        if "GROQ_API_KEY" in os.environ:
            saved = os.environ.pop("GROQ_API_KEY")
            try:
                client = GroqDFIRClient(api_key="")
                assert not client.available, "Client should not be available without API key"
            finally:
                os.environ["GROQ_API_KEY"] = saved
        else:
            client = GroqDFIRClient(api_key="")
            assert not client.available, "Client should not be available without API key"
            assert not client._call_groq([]), "Should return empty string without API"

    def test_groq_client_accepts_api_key(self):
        """Client accepts API key via constructor."""
        from src.agent.groq_client import GroqDFIRClient
        client = GroqDFIRClient(api_key="test-key-12345")
        assert client.api_key == "test-key-12345"

    def test_groq_client_default_model(self):
        """Client uses default model when none specified."""
        from src.agent.groq_client import GroqDFIRClient, DEFAULT_MODEL
        client = GroqDFIRClient(api_key="test-key-12345")
        assert client.model == DEFAULT_MODEL

    def test_groq_client_fallback_models(self):
        """Fallback models list is non-empty and doesn't duplicate primary."""
        from src.agent.groq_client import FALLBACK_MODELS, DEFAULT_MODEL
        assert len(FALLBACK_MODELS) > 0
        assert DEFAULT_MODEL not in FALLBACK_MODELS

    def test_groq_client_system_prompt(self):
        """System prompt is set and contains DFIR guidance."""
        from src.agent.groq_client import SYSTEM_PROMPT_DFIR
        assert len(SYSTEM_PROMPT_DFIR) > 200
        assert "DFIR" in SYSTEM_PROMPT_DFIR or "Digital Forensics" in SYSTEM_PROMPT_DFIR

    def test_groq_client_reset_conversation(self):
        """reset_conversation clears history."""
        from src.agent.groq_client import GroqDFIRClient
        client = GroqDFIRClient(api_key="test-key-12345")
        client.conversation_history = [{"role": "user", "content": "test"}]
        client.reset_conversation()
        assert client.conversation_history == []


class TestOutputParser:
    """Test output parsing logic."""

    def test_extract_json_from_direct(self):
        """Direct JSON parsing works."""
        from src.agent.output_parser import extract_json_from_text
        result = extract_json_from_text('{"tools": [{"name": "fs_list_files"}]}')
        assert result is not None
        assert "tools" in result

    def test_extract_json_from_code_block(self):
        """JSON in markdown code block is extracted."""
        from src.agent.output_parser import extract_json_from_text
        text = 'Some text\n```json\n{"tools": ["fs_list_files"]}\n```\nMore text'
        result = extract_json_from_text(text)
        assert result is not None
        assert "tools" in result

    def test_extract_json_invalid_returns_none(self):
        """Invalid JSON returns None."""
        from src.agent.output_parser import extract_json_from_text
        result = extract_json_from_text("This is not JSON")
        assert result is None

    def test_parse_tool_decision_json(self):
        """Parse tool decision from proper JSON."""
        from src.agent.output_parser import parse_tool_decision
        tools = parse_tool_decision('{"tools": [{"name": "fs_list_files", "reasoning": "check files"}]}')
        assert "fs_list_files" in tools

    def test_parse_tool_decision_flat_list(self):
        """Parse tool decision from flat JSON list."""
        from src.agent.output_parser import parse_tool_decision
        tools = parse_tool_decision('{"next_tools": ["fs_list_files", "verify_hash"]}')
        assert "fs_list_files" in tools
        assert "verify_hash" in tools

    def test_parse_tool_decision_action_context(self):
        """Tool name after action prefix is matched."""
        from src.agent.output_parser import parse_tool_decision
        tools = parse_tool_decision("I recommend we run fs_list_files next")
        assert "fs_list_files" in tools

    def test_parse_tool_decision_prose_not_matched(self):
        """Tool name in prose without action context is NOT matched (prevents phantom calls)."""
        from src.agent.output_parser import parse_tool_decision
        # The LLM saying "we already tried fs_list_files" should NOT trigger it
        tools = parse_tool_decision("We already tried fs_list_files and it failed. Let's try verify_hash instead.")
        assert "fs_list_files" not in tools  # Should NOT be extracted
        assert "verify_hash" in tools  # Should be extracted (after "try")

    def test_parse_report_valid(self):
        """Parse report from valid JSON."""
        from src.agent.output_parser import parse_report
        report = parse_report('{"summary": "test", "findings": []}')
        assert report["summary"] == "test"

    def test_parse_report_invalid_returns_raw(self):
        """Parse report from invalid JSON returns raw text."""
        from src.agent.output_parser import parse_report
        report = parse_report("Not JSON at all")
        assert "raw_report" in report


class TestToolSelector:
    """Test tool selection logic."""

    def test_suggest_next_tools_known_phase(self):
        """suggest_next_tools returns tools for known phases."""
        from src.agent.tool_selector import suggest_next_tools
        tools = suggest_next_tools("initial_triage")
        assert len(tools) > 0
        assert all("tool" in t and "priority" in t for t in tools)

    def test_suggest_next_tools_unknown_phase(self):
        """suggest_next_tools returns empty for unknown phases."""
        from src.agent.tool_selector import suggest_next_tools
        tools = suggest_next_tools("nonexistent_phase")
        assert tools == []

    def test_suggest_next_tools_ordered(self):
        """suggest_next_tools returns tools ordered by priority."""
        from src.agent.tool_selector import suggest_next_tools
        tools = suggest_next_tools("filesystem_analysis")
        for i in range(len(tools) - 1):
            assert tools[i]["priority"] <= tools[i + 1]["priority"]

    def test_get_tool_for_artifact(self):
        """get_tool_for_artifact returns correct tool for artifact type."""
        from src.agent.tool_selector import get_tool_for_artifact
        assert get_tool_for_artifact("partition_table") == "fs_partition_scan"
        assert get_tool_for_artifact("process_list") == "mem_list_processes"
        assert get_tool_for_artifact("network_connections") == "mem_scan_network"
        assert get_tool_for_artifact("yara_match") == "scan_yara"

    def test_get_tool_for_unknown_artifact(self):
        """get_tool_for_artifact returns default for unknown type."""
        from src.agent.tool_selector import get_tool_for_artifact
        assert get_tool_for_artifact("unknown_type") == "fs_partition_scan"

    def test_get_fallback_chain(self):
        """get_fallback_chain returns alternatives for known tools."""
        from src.agent.tool_selector import get_fallback_chain
        chain = get_fallback_chain("mem_list_processes")
        assert len(chain) > 0
        assert "mem_analyze" in chain

    def test_get_fallback_chain_default(self):
        """get_fallback_chain returns default for unknown tools."""
        from src.agent.tool_selector import get_fallback_chain
        chain = get_fallback_chain("unknown_tool")
        assert len(chain) > 0  # Should return default fallback
