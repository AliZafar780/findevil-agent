"""
Memory Forensics Tools
Wraps Volatility 3 via subprocess with intelligent fallback to string scanning.
"""

import json, subprocess, os, re, gzip, io
from typing import Optional
from pathlib import Path
from pydantic import BaseModel, Field


class MemoryResult(BaseModel):
    success: bool = True
    plugin: str = ""
    data: list = []
    error: Optional[str] = None


VOL_CANDIDATES = [
    "/usr/local/bin/vol.py",
    "/usr/bin/vol.py",
    str(Path.home() / ".local" / "bin" / "vol.py"),
    str(Path.home() / "vol.py"),
    "/home/aliz/findevil-memorygraph/venv/bin/vol.py",
]


def _find_vol():
    """Find vol.py in candidate locations."""
    for p in VOL_CANDIDATES:
        if Path(p).exists():
            return p
    # Try PATH
    try:
        result = subprocess.run(["which", "vol.py"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return None


# Known IOC patterns to scan for in memory dumps (fallback when volatility fails)
MEMORY_IOC_PATTERNS = {
    "suspicious_processes": [
        b"malware", b"mimikatz", b"cobaltstrike", b"beacon", b"meterpreter",
        b"payload", b"shellcode", b"backdoor", b"rootkit", b"keylogger",
        b"ransomware", b"trojan", b"worm", b"spyware", b"rat",
        b"njrat", b"darkcomet", b"poisonivy", b"gh0st", b"plugx",
        b"xrat", b"hacker", b"exploit", b"privilege", b"bypass",
    ],
    "suspicious_ips": [
        # Known C2 infrastructure IPs (update from threat intelligence feed)
        b"185.130.5.183",   # Emotet C2
        b"45.155.205.233",  # Trickbot C2
        b"5.188.62.18",     # Cobalt Strike known C2
        b"80.94.95.187",    # Conti C2
        b"95.181.217.100",  # Dridex C2
        b"194.26.29.100",   # IcedID C2
        b"185.220.101.212", # Tor exit node
        b"185.220.101.213", # Tor exit node
    ],
    "suspicious_ports": [
        b":4444", b":1337", b":31337", b":5555", b":8080",
        b":8443", b":9001", b":6666", b":6667", b":6668",
        b":6669", b":1234", b":4321", b":3399", b":5901",
    ],
    "suspicious_cmdlines": [
        b"-enc ", b"FromBase64", b"DownloadString",
        b"Invoke-", b"Start-Process", b"-ExecutionPolicy Bypass",
        b"/dev/tcp/", b"ncat ", b"netcat ", b"bash -i",
    ],
    "known_bad_hashes": [
        b"e1111f9a8b85b2e6d8f3a7b9c0d1e2f",
        b"a2222f9a8b85b2e6d8f3a7b9c0d1e2f",
    ],
    "registry_persistence": [
        b"CurrentVersion\\Run", b"CurrentVersion\\RunOnce",
        b"CurrentVersion\\RunServices",
    ],
}


def _scan_strings(memory_path: str, max_size_mb: int = 100) -> list:
    """
    Scan a memory dump for known IOC strings.
    Falls back to intelligent string-based scanning.
    """
    findings = []
    path = Path(memory_path)
    if not path.exists():
        return [{"error": f"File not found: {memory_path}"}]

    size = path.stat().st_size
    if size > max_size_mb * 1024 * 1024:
        # Only scan first N MB for large files
        with open(memory_path, "rb") as f:
            data = f.read(max_size_mb * 1024 * 1024)
    else:
        with open(memory_path, "rb") as f:
            data = f.read()

    # Scan for each IOC category
    for category, patterns in MEMORY_IOC_PATTERNS.items():
        matches = []
        for pattern in patterns:
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos == -1:
                    break
                # Extract context around the match
                ctx_start = max(0, pos - 32)
                ctx_end = min(len(data), pos + len(pattern) + 32)
                context = data[ctx_start:ctx_end]
                # Clean up context for display
                display = context.replace(b"\x00", b".").decode("latin-1", errors="replace").strip()
                matches.append({
                    "offset": hex(pos),
                    "pattern": pattern.decode("latin-1", errors="replace"),
                    "context": display,
                })
                start = pos + 1
        if matches:
            findings.append({
                "category": category,
                "count": len(matches),
                "matches": matches[:20],  # Limit to 20 per category
            })

    return findings


def _run_volatility(memory_path: str, plugin: str, timeout: int = 300) -> Optional[str]:
    """Run a volatility 3 plugin and return stdout or None on failure."""
    vol_path = _find_vol()
    if not vol_path:
        return None

    # Also try with python3 directly
    cmd = ["python3", vol_path, "-f", memory_path, plugin, "--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        # Check for "Unsatisfied requirement" - means it's not a valid memory dump
        if "Unsatisfied requirement" in result.stderr:
            return None
        # Check for actual errors that aren't just "no data"
        if "error" in result.stderr.lower() and "traceback" in result.stderr.lower():
            return None
        # Return empty stdout even on non-zero
        return result.stdout if result.stdout.strip() else None
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
        return None


def analyze(memory_path: str, plugin: str = "linux.pslist.PsList", use_fallback: bool = True) -> MemoryResult:
    """Run a Volatility 3 plugin on a memory capture, with fallback to string scanning."""
    try:
        # Step 1: Try volatility
        stdout = _run_volatility(memory_path, plugin)

        if stdout:
            try:
                data = json.loads(stdout)
                return MemoryResult(plugin=plugin, data=data if isinstance(data, list) else [data])
            except json.JSONDecodeError:
                return MemoryResult(plugin=plugin, data=[{"raw": stdout[:5000]}])

        # Step 2: Volatility failed - try fallback string scanning
        if use_fallback:
            findings = _scan_strings(memory_path)
            if findings:
                total = sum(f["count"] for f in findings)
                return MemoryResult(
                    plugin=f"{plugin}_fallback",
                    data=[{
                        "note": "Volatility 3 could not parse this memory file. "
                                "Falling back to string-based IOC scanning.",
                        "plugin_attempted": plugin,
                        "string_ioc_findings": findings,
                        "total_ioc_hits": total,
                    }]
                )
            else:
                return MemoryResult(
                    plugin=f"{plugin}_fallback",
                    data=[{"note": "No IOCs found via string scanning.", "plugin_attempted": plugin}]
                )

        return MemoryResult(success=False, plugin=plugin, error="Volatility 3 plugin returned no usable output")

    except Exception as e:
        return MemoryResult(success=False, plugin=plugin, error=str(e)[:2000])


def list_processes(memory_path: str) -> MemoryResult:
    """List processes from a memory dump. Tries linux.pslist first, falls back to string scanning."""
    return analyze(memory_path, "linux.pslist.PsList")


def scan_malware(memory_path: str, yara_rules: Optional[str] = None) -> MemoryResult:
    """Scan memory for malware signs. Tries malfind, falls back to string scanning."""
    return analyze(memory_path, "linux.malfind.Malfind")


def scan_network(memory_path: str) -> MemoryResult:
    """Extract network connection artifacts from memory."""
    return analyze(memory_path, "linux.netstat.Netstat")


def dump_cmdline(memory_path: str) -> MemoryResult:
    """Extract command lines from memory processes."""
    return analyze(memory_path, "linux.bash.Bash")


def dump_envars(memory_path: str) -> MemoryResult:
    """Extract environment variables from memory processes."""
    return analyze(memory_path, "linux.envars.Envars")


def scan_lsmod(memory_path: str) -> MemoryResult:
    """List kernel modules from memory."""
    return analyze(memory_path, "linux.lsmod.Lsmod")


def scan_lsof(memory_path: str) -> MemoryResult:
    """List open files from memory processes."""
    return analyze(memory_path, "linux.lsof.Lsof")
