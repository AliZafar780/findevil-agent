"""Shared test helpers — imported by conftest.py and test modules."""

import json as _json
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).parent.parent))

EVIDENCE_ROOT = _Path("/evidence/cases/test.raw")
HAS_EVIDENCE = EVIDENCE_ROOT.exists()


async def _call(client, name: str, args: dict) -> dict:
    """Call a tool and return parsed result."""
    result = await client.call_tool(name, args)
    if isinstance(result, str):
        return _json.loads(result)
    return result if isinstance(result, dict) else {"success": False, "error": str(result)}
