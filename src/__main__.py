"""
FindEvil Agent — Main Entry Point
Allows `python -m src` to run the CLI or MCP server.

Usage:
  python -m src                         # Show help
  python -m src investigate /evidence/cases/image.raw
  python -m src serve
  python -m src tools
  python -m src check
"""

import sys

if __name__ == "__main__":
    # If no args or 'serve' is passed, run the MCP server
    # Otherwise, route through the CLI
    if len(sys.argv) == 1:
        print("FindEvil Agent v2.0.0")
        print("Usage: python -m src <command> [options]")
        print()
        print("Commands:")
        print("  investigate   Run full automated DFIR investigation")
        print("  serve         Start MCP server for integration")
        print("  tools         List all forensic tools")
        print("  tool          Run a single forensic tool")
        print("  check         Verify environment")
        print("  create-test-image  Create test evidence")
        print()
        print("Examples:")
        print("  python -m src investigate /evidence/cases/test.raw")
        print("  python -m src serve")
        print("  python -m src check")
        sys.exit(0)
    elif len(sys.argv) >= 2 and sys.argv[1] == "serve":
        # Start MCP server directly (no CLI overhead)
        import asyncio

        from .server import main as server_main

        asyncio.run(server_main())
    else:
        # Route through CLI
        from .cli import main as cli_main

        cli_main()
