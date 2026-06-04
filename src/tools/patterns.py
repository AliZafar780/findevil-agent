"""
Pattern Matching and YARA Tools
Wraps yara and provides built-in detection rules.
"""
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


class PatternResult(BaseModel):
    success: bool = True
    data: list = []
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
    strings:
        $ip1 = "192.168.1.100:4444" nocase
        $ip2 = "10.10.10.10:1337" nocase
        $domain1 = "malware.evil.com" nocase
        $domain2 = "c2server.bad" nocase
        $url1 = "http://evil.com/payload" nocase
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
        description = "Detects suspicious file extensions"
    strings:
        $e1 = ".ps1" nocase
        $e2 = ".vbs" nocase
        $e3 = ".js" nocase
        $e4 = ".vba" nocase
        $e5 = ".hta" nocase
        $e6 = ".scr" nocase
        $e7 = ".bat" nocase
        $e8 = ".cmd" nocase
        $e9 = ".jar" nocase
    condition:
        any of them
}
"""


def scan_yara(target_path: str, rules_path: Optional[str] = None, rules_content: Optional[str] = None) -> PatternResult:
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


def scan_with_builtin_rules(target_path: str) -> PatternResult:
    """Scan using built-in FindEvil YARA rules."""
    return scan_yara(target_path, rules_content=BUILTIN_RULES)


def search_text_patterns(file_path: str, patterns: list) -> PatternResult:
    """Search for text patterns in a file using grep-like matching."""
    try:
        matches = []
        content = Path(file_path).read_text(errors="replace")

        for pattern in patterns:
            for i, line in enumerate(content.split("\n"), 1):
                if pattern.lower() in line.lower():
                    matches.append({
                        "pattern": pattern,
                        "line": i,
                        "context": line[:200],
                    })

        return PatternResult(
            success=True,
            match_count=len(matches),
            data=matches[:1000],
        )
    except Exception as e:
        return PatternResult(success=False, error=str(e))
