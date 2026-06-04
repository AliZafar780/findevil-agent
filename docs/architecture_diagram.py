#!/usr/bin/env python3
"""Generate Architecture Diagram SVG for Find Evil! Agent submission."""
import xml.etree.ElementTree as ET

SVG_NS = "http://www.w3.org/2000/svg"

def svg_element(tag, **attrs):
    return ET.Element(f"{{{SVG_NS}}}{tag}", **{k.replace('_', '-'): str(v) for k, v in attrs.items()})

def text(x, y, content, size=14, weight="normal", fill="#333", anchor="start"):
    t = svg_element("text", x=x, y=y, font_size=size, font_weight=weight, fill=fill, text_anchor=anchor)
    t.text = content
    return t

def rect(x, y, w, h, fill="#e0e0e0", stroke="#333", rx=6):
    return svg_element("rect", x=x, y=y, width=w, height=h, fill=fill, stroke=stroke, rx=rx)

def arrow(x1, y1, x2, y2):
    return svg_element("line", x1=x1, y1=y1, x2=x2, y2=y2, stroke="#666", stroke_width=2,
                       marker_end="url(#arrowhead)")

def build_diagram():
    root = svg_element("svg", width=900, height=700, xmlns=SVG_NS)
    root.append(svg_element("defs"))
    
    # Arrow marker
    marker = svg_element("marker", id="arrowhead", markerWidth=10, markerHeight=7, refX=10, refY=3.5, orient="auto")
    marker.append(svg_element("polygon", points="0 0, 10 3.5, 0 7", fill="#666"))
    root.find(f"{{{SVG_NS}}}defs").append(marker)
    
    # Title
    root.append(text(450, 35, "FindEvil Agent — Architecture", size=22, weight="bold", anchor="middle"))
    root.append(text(450, 55, "Custom MCP Server + Self-Correcting Agent Loop", size=14, fill="#666", anchor="middle"))
    
    # ── Layer 1: MCP Client ──
    root.append(rect(350, 80, 200, 60, "#4A90D9"))
    root.append(text(450, 110, "MCP Client", size=16, weight="bold", fill="white", anchor="middle"))
    root.append(text(450, 130, "Claude Code / OpenClaw", size=12, fill="#cce5ff", anchor="middle"))
    
    # Arrow down
    root.append(arrow(450, 140, 450, 180))
    
    # ── Layer 2: MCP Server ──
    root.append(rect(100, 180, 700, 200, "#F5F5F5", "#4A90D9"))
    root.append(text(450, 205, "FindEvil MCP Server (Python)", size=16, weight="bold", anchor="middle"))
    root.append(text(450, 225, "Type-safe functions · Read-only evidence enforcement · Full audit trail", size=11, fill="#666", anchor="middle"))
    
    # Tool groups
    tools = [
        (130, 245, "#E8F5E9", "Disk/FS Tools", "fs_partition_scan\nfs_list_files\nfs_extract_file\nfs_file_metadata"),
        (290, 245, "#E3F2FD", "Memory Tools", "mem_analyze\nmem_list_processes\nmem_scan_network"),
        (450, 245, "#FFF3E0", "Network Tools", "pcap_analyze\npcap_list_protocols"),
        (610, 245, "#F3E5F5", "Utility Tools", "verify_hash\nlist_evidence\nbenchmark_accuracy"),
        (130, 320, "#FFEBEE", "Registry Tools", "reg_analyze_hive"),
        (290, 320, "#E0F7FA", "Carving Tools", "carve_files\nscan_yara"),
    ]
    
    for x, y, color, title, items in tools:
        root.append(rect(x, y, 140, 70, color, "#999"))
        root.append(text(x+70, y+18, title, size=10, weight="bold", fill="#333", anchor="middle"))
        for i, line in enumerate(items.split('\n')):
            root.append(text(x+70, y+33+i*12, line, size=9, fill="#555", anchor="middle"))
    
    # Arrow down
    root.append(arrow(450, 380, 450, 420))
    
    # ── Layer 3: SIFT Workstation ──
    root.append(rect(200, 420, 500, 80, "#2E7D32", "#1B5E20"))
    root.append(text(450, 450, "SIFT Workstation", size=16, weight="bold", fill="white", anchor="middle"))
    root.append(text(450, 470, "200+ forensic tools: TSK, Volatility 3, YARA, foremost, tshark, ...", size=11, fill="#c8e6c9", anchor="middle"))
    
    # Arrow down
    root.append(arrow(450, 500, 450, 540))
    
    # ── Layer 4: Evidence (Read-Only) ──
    root.append(rect(200, 540, 220, 60, "#C62828", "#B71C1C"))
    root.append(text(310, 565, "EVIDENCE", size=14, weight="bold", fill="white", anchor="middle"))
    root.append(text(310, 582, "Read-Only 🔒", size=11, fill="#ffcdd2", anchor="middle"))
    
    # Arrow to results
    root.append(rect(480, 540, 220, 60, "#1565C0", "#0D47A1"))
    root.append(text(590, 565, "RESULTS", size=14, weight="bold", fill="white", anchor="middle"))
    root.append(text(590, 582, "Audit Trail + Carved Files", size=11, fill="#bbdefb", anchor="middle"))
    
    # Bottom annotations
    root.append(text(450, 635, "Security Boundaries", size=13, weight="bold", fill="#333", anchor="middle"))
    root.append(text(450, 655, "Architectural guardrails enforced at MCP server level — not prompt-based", size=11, fill="#666", anchor="middle"))
    
    return root

if __name__ == "__main__":
    import xml.etree.ElementTree as ET
    tree = ET.ElementTree(build_diagram())
    tree.write("/home/aliz/findevil-memorygraph/docs/architecture.svg", xml_declaration=True, encoding="utf-8")
    print("✅ Architecture diagram saved to docs/architecture.svg")
