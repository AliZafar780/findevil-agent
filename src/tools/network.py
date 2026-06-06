"""
Network Forensics Tools
Wraps tshark for PCAP analysis.
"""

import json
import subprocess
from typing import Any, Optional

from pydantic import BaseModel

from src.tools.tool_resolver import find_tool

TSHARK_PATH = find_tool("tshark") or "/usr/bin/tshark"  # fallback for backward compat


class NetworkResult(BaseModel):
    success: bool = True
    data: list[dict[str, Any]] = []
    error: Optional[str] = None
    packet_count: int = 0


def analyze(
    pcap_path: str,
    display_filter: str = "",
    max_packets: int = 100,
    fields: str = "frame.number,ip.src,ip.dst,frame.protocols,_ws.col.Info",
) -> NetworkResult:
    """Analyze a PCAP file with tshark."""
    try:
        cmd = [TSHARK_PATH, "-r", pcap_path, "-T", "json"]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        if max_packets > 0:
            cmd.extend(["-c", str(max_packets)])

        # Add fields
        field_list = [f.strip() for f in fields.split(",")]
        for field in field_list:
            if field:
                cmd.extend(["-e", field])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if not result.returncode == 0:
            # tshark often returns non-zero for warnings
            pass

        packets = []
        if result.stdout.strip():
            try:
                parsed = json.loads(result.stdout)
                for p in parsed if isinstance(parsed, list) else [parsed]:
                    layers = p.get("_source", {}).get("layers", {})
                    packet = {
                        "frame_number": (
                            layers.get("frame.number", [""])[0]
                            if isinstance(layers.get("frame.number"), list)
                            else layers.get("frame.number", "")
                        ),
                        "ip_src": (
                            layers.get("ip.src", [""])[0]
                            if isinstance(layers.get("ip.src"), list)
                            else layers.get("ip.src", "")
                        ),
                        "ip_dst": (
                            layers.get("ip.dst", [""])[0]
                            if isinstance(layers.get("ip.dst"), list)
                            else layers.get("ip.dst", "")
                        ),
                        "protocols": (
                            layers.get("frame.protocols", [""])[0]
                            if isinstance(layers.get("frame.protocols"), list)
                            else layers.get("frame.protocols", "")
                        ),
                        "info": (
                            layers.get("_ws.col.Info", [""])[0]
                            if isinstance(layers.get("_ws.col.Info"), list)
                            else layers.get("_ws.col.Info", "")
                        ),
                    }
                    packets.append(packet)
            except json.JSONDecodeError:
                packets.append({"raw": result.stdout[:5000]})

        return NetworkResult(
            success=True,
            packet_count=len(packets),
            data=packets,
        )
    except subprocess.TimeoutExpired:
        return NetworkResult(success=False, error="tshark timed out after 120s")
    except FileNotFoundError:
        return NetworkResult(
            success=False, error="tshark not found. Install: sudo apt-get install tshark"
        )
    except Exception as e:
        return NetworkResult(success=False, error=str(e))


def list_protocols(pcap_path: str) -> NetworkResult:
    """List all protocols in a PCAP file."""
    try:
        cmd = [TSHARK_PATH, "-r", pcap_path, "-z", "io,phs", "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        return NetworkResult(
            success=result.returncode in (0, 1),
            data=[{"protocol_hierarchy": result.stdout}],
        )
    except Exception as e:
        return NetworkResult(success=False, error=str(e))



