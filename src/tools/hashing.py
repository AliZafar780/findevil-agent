"""
Hashing and Integrity Tools
Wraps sha256sum, md5sum, sha1sum, and hashdeep.
"""

import subprocess
from typing import Optional

from pydantic import BaseModel


class HashResult(BaseModel):
    success: bool = True
    data: list = []
    error: Optional[str] = None
    algorithm: str = "sha256"
    hash_value: str = ""


def compute_hash(file_path: str, algorithm: str = "sha256") -> HashResult:
    """Compute cryptographic hash of a file."""
    try:
        hash_cmd = {
            "md5": "/usr/bin/md5sum",
            "sha1": "/usr/bin/sha1sum",
            "sha256": "/usr/bin/sha256sum",
            "sha512": "/usr/bin/sha512sum",
        }.get(algorithm)

        if not hash_cmd:
            return HashResult(success=False, error=f"Unsupported algorithm: {algorithm}")

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


def compute_deep_hash(image_path: str) -> HashResult:
    """Compute hashes using hashdeep for recursive directory hashing."""
    try:
        result = subprocess.run(
            ["/usr/bin/hashdeep", "-l", "-c", "sha256", image_path],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode == 0:
            entries = []
            for line in result.stdout.strip().split("\n"):
                if line.strip() and not line.startswith("%"):
                    parts = line.split(",", 1)
                    if len(parts) == 2:
                        entries.append({"hash": parts[0], "file": parts[1]})

            return HashResult(
                success=True,
                algorithm="sha256",
                data=entries[:1000],
            )
        else:
            return HashResult(success=False, error=result.stderr[:1000])
    except FileNotFoundError:
        return HashResult(success=False, error="hashdeep not found")
    except Exception as e:
        return HashResult(success=False, error=str(e))


def verify_hash_match(file_path: str, expected_hash: str, algorithm: str = "sha256") -> HashResult:
    """Verify a file matches an expected hash."""
    result = compute_hash(file_path, algorithm)
    if result.success:
        match = result.hash_value.lower() == expected_hash.lower()
        return HashResult(
            success=True,
            algorithm=algorithm,
            hash_value=result.hash_value,
            data=[
                {
                    "file": file_path,
                    "expected": expected_hash,
                    "computed": result.hash_value,
                    "match": match,
                }
            ],
        )
    return result
