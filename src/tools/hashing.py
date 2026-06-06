"""
Hashing and Integrity Tools
Wraps sha256sum, md5sum, sha1sum, and hashdeep.
"""

import subprocess
from typing import Any, Optional

from pydantic import BaseModel


class HashResult(BaseModel):
    success: bool = True
    data: list[dict[str, Any]] = []
    error: Optional[str] = None
    algorithm: str = "sha256"
    hash_value: str = ""


def compute_hash(file_path: str, algorithm: str = "sha256") -> HashResult:
    """Compute cryptographic hash of a file."""
    try:
        from src.tools.tool_resolver import find_tool

        HASH_TOOLS = {
            "md5": "md5sum",
            "sha1": "sha1sum",
            "sha256": "sha256sum",
            "sha512": "sha512sum",
        }
        tool_name = HASH_TOOLS.get(algorithm)
        if not tool_name:
            return HashResult(success=False, error=f"Unsupported algorithm: {algorithm}")

        hash_cmd = find_tool(tool_name)
        if not hash_cmd:
            return HashResult(
                success=False,
                error=f"Hash tool '{tool_name}' not found. Install coreutils: sudo apt-get install coreutils",
            )

        result = subprocess.run([hash_cmd, file_path], capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            hash_value = result.stdout.split()[0] if result.stdout else ""
            return HashResult(
                success=True,
                algorithm=algorithm,
                hash_value=hash_value,
                data=[{"algorithm": algorithm, "hash": hash_value, "file": file_path}],
            )
        else:
            return HashResult(success=False, error=result.stderr[:1000])
    except subprocess.TimeoutExpired:
        return HashResult(success=False, error="Hash computation timed out (300s)")
    except FileNotFoundError:
        return HashResult(success=False, error=f"{algorithm}sum not found")
    except Exception as e:
        return HashResult(success=False, error=str(e))
