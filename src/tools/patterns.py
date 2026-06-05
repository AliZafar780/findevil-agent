"""
Pattern Matching and YARA Tools
Wraps yara and provides built-in detection rules.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel


class PatternResult(BaseModel):
    success: bool = True
    data: list[dict[str, Any]] = []
    error: Optional[str] = None
    match_count: int = 0


# Built-in YARA rules for common DFIR detections
BUILTIN_RULES = """
rule SuspiciousProcessNames {
    meta:
        description = "Detects suspicious process names in memory"
        author = "FindEvil Agent"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "meterpreter" nocase
        $s3 = "cobaltstrike" nocase
        $s4 = "beacon" nocase
        $s5 = "payload" nocase
        $s6 = "keylog" nocase
        $s7 = "ransomware" nocase
        $s8 = "inject" nocase
        $s9 = "psexec" nocase
        $s10 = "wce.exe" nocase
        $s11 = "gsecdump" nocase
        $s12 = "fgdump" nocase
        $s13 = "procdump" nocase
    condition:
        any of them
}

rule KnownMaliciousHashes {
    meta:
        description = "Detects known malicious file hashes"
    strings:
        $h1 = "e111c9cf0c7c8d5e1c3c6b0e5f1a2b3c4d5e6f7a" nocase
    condition:
        any of them
}

rule NetworkIndicators {
    meta:
        description = "Detects network indicators of compromise"
        severity = "high"
        author = "FindEvil Agent"
    strings:
        $ip1 = "185.130.5.183" nocase
        $ip2 = "45.155.205.233" nocase
        $domain1 = ".tor2web." nocase
        $domain2 = ".onion" nocase
        $url1 = "pastebin.com" nocase
        $url2 = "raw.githubusercontent.com" nocase
    condition:
        any of them
}

rule RegistryPersistence {
    meta:
        description = "Detects registry persistence mechanisms"
    strings:
        $r1 = "CurrentVersion\\Run" nocase
        $r2 = "CurrentVersion\\RunOnce" nocase
        $r3 = "Userinit" nocase
        $r4 = "ShellServiceObjectDelayLoad" nocase
        $r5 = "BootExecute" nocase
        $r6 = "ImageFileExecutionOptions" nocase
    condition:
        any of them
}

rule SuspiciousFileExtensions {
    meta:
        description = "Detects suspicious file extensions often used in malware delivery"
        severity = "medium"
        author = "FindEvil Agent"
    strings:
        $e1 = ".hta" nocase
        $e2 = ".scr" nocase
        $e3 = ".vbe" nocase
        $e4 = ".jse" nocase
        $e5 = ".wsf" nocase
        $e6 = ".docm" nocase
        $e7 = ".pptm" nocase
        $e8 = ".xlsm" nocase
        $e9 = ".cpl" nocase
    condition:
        any of them
}
"""


def scan_yara(
    target_path: str, rules_path: Optional[str] = None, rules_content: Optional[str] = None
) -> PatternResult:
    """Scan a file or directory with YARA rules."""
    try:
        # Resolve rules
        if rules_content:
            content = rules_content
        elif rules_path:
            with open(rules_path) as f:
                content = f.read()
        else:
            content = BUILTIN_RULES

        # Write rules to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yara", delete=False) as f:
            f.write(content)
            tmp_rules = f.name

        try:
            cmd = ["/usr/bin/yara", "-w", tmp_rules, target_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            matches = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    parts = line.split(maxsplit=1)
                    rule_name = parts[0] if parts else ""
                    matched_file = parts[1] if len(parts) > 1 else target_path
                    matches.append({"rule": rule_name, "target": matched_file})

            return PatternResult(
                success=True,
                match_count=len(matches),
                data=matches,
            )
        finally:
            os.unlink(tmp_rules)
    except subprocess.TimeoutExpired:
        return PatternResult(success=False, error="YARA scan timed out after 120s")
    except FileNotFoundError:
        return PatternResult(success=False, error="yara not found at /usr/bin/yara")
    except Exception as e:
        return PatternResult(success=False, error=str(e))


def search_text_patterns(file_path: str, patterns: list[str]) -> PatternResult:
    """Search for text patterns in a file using grep-like matching."""
    try:
        matches = []
        content = Path(file_path).read_text(errors="replace")

        for pattern in patterns:
            for i, line in enumerate(content.split("\n"), 1):
                if pattern.lower() in line.lower():
                    matches.append(
                        {
                            "pattern": pattern,
                            "line": i,
                            "context": line[:200],
                        }
                    )

        return PatternResult(
            success=True,
            match_count=len(matches),
            data=matches[:1000],
        )
    except Exception as e:
        return PatternResult(success=False, error=str(e))
