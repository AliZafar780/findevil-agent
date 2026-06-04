"""
Network Forensics Tools
Wraps tshark for PCAP analysis.
"""
import subprocess
import json
from typing import Optional
from pydantic import BaseModel, Field


class NetworkResult(BaseModel):
    success: bool = True
    data: list = []
    error: Optional[str] = None
    packet_count: int = 0


def analyze(pcap_path: str, display_filter: str = "", max_packets: int = 100,
            fields: str = "frame.number,ip.src,ip.dst,frame.protocols,_ws.col.Info") -> NetworkResult:
    """Analyze a PCAP file with tshark."""
    try:
        cmd = ["/usr/bin/tshark", "-r", pcap_path, "-T", "json"]
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
                        "frame_number": layers.get("frame.number", [""])[0] if isinstance(layers.get("frame.number"), list) else layers.get("frame.number", ""),
                        "ip_src": layers.get("ip.src", [""])[0] if isinstance(layers.get("ip.src"), list) else layers.get("ip.src", ""),
                        "ip_dst": layers.get("ip.dst", [""])[0] if isinstance(layers.get("ip.dst"), list) else layers.get("ip.dst", ""),
                        "protocols": layers.get("frame.protocols", [""])[0] if isinstance(layers.get("frame.protocols"), list) else layers.get("frame.protocols", ""),
                        "info": layers.get("_ws.col.Info", [""])[0] if isinstance(layers.get("_ws.col.Info"), list) else layers.get("_ws.col.Info", ""),
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
        return NetworkResult(success=False, error="tshark not found. Install: sudo apt-get install tshark")
    except Exception as e:
        return NetworkResult(success=False, error=str(e))


def list_protocols(pcap_path: str) -> NetworkResult:
    """List all protocols in a PCAP file."""
    try:
        cmd = ["/usr/bin/tshark", "-r", pcap_path, "-z", "io,phs", "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        return NetworkResult(
            success=result.returncode in (0, 1),
            data=[{"protocol_hierarchy": result.stdout}],
        )
    except Exception as e:
        return NetworkResult(success=False, error=str(e))


def extract_conversations(pcap_path: str) -> NetworkResult:
    """Extract IPv4 conversations from a PCAP."""
    try:
        cmd = ["/usr/bin/tshark", "-r", pcap_path, "-z", "conv,ip", "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        conversations = []
        for line in result.stdout.split("\n"):
            if line.strip() and not line.startswith("=") and not line.startswith(" ") and "|" in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 3:
                    conversations.append({
                        "src_dst": parts[0],
                        "packets": parts[1],
                        "bytes": parts[2],
                    })

        return NetworkResult(
            success=result.returncode in (0, 1),
            data=conversations[:100],
        )
    except Exception as e:
        return NetworkResult(success=False, error=str(e))


def extract_http_objects(pcap_path: str) -> NetworkResult:
    """Extract HTTP objects from a PCAP using tshark."""
    try:
        cmd = ["/usr/bin/tshark", "-r", pcap_path, "--export-objects", "http,/results/carved/http_objects"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        from pathlib import Path
        export_dir = Path("/results/carved/http_objects")
        objects = []
        if export_dir.exists():
            for f in export_dir.iterdir():
                if f.is_file():
                    objects.append({"name": f.name, "size": f.stat().st_size})

        return NetworkResult(
            success=True,
            data=[{"http_objects": objects, "count": len(objects)}],
        )
    except Exception as e:
        return NetworkResult(success=False, error=str(e))
