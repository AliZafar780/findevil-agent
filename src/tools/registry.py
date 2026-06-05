"""
Windows Registry Analysis Tools
Wraps regipy and reglookup for registry hive analysis.
"""

import subprocess
from typing import Optional

from pydantic import BaseModel


class RegistryResult(BaseModel):
    success: bool = True
    data: list = []
    error: Optional[str] = None
    key_count: int = 0


def query(hive_path: str, key: str = "/", recursive: bool = False) -> RegistryResult:
    """Query a Windows Registry hive file using regipy."""
    try:
        from regipy import RegistryHive

        hive = RegistryHive(hive_path)
        result_data = []

        if recursive:
            for entry in hive.recurse_subkeys(key):
                entry_data = {
                    "path": entry.path,
                    "timestamp": str(entry.timestamp) if entry.timestamp else None,
                }
                # Safely get values
                try:
                    values = {}
                    for v in getattr(entry, "values", []):
                        try:
                            values[v.name] = str(v.value)[:200]
                        except Exception:
                            values[v.name] = "<binary>"
                    entry_data["values"] = values
                except Exception:
                    entry_data["values"] = {}
                result_data.append(entry_data)
                if len(result_data) >= 500:
                    break
        else:
            # Just get the subkeys at the given level
            try:
                for entry in hive.get_key(key).iter_subkeys():
                    result_data.append(
                        {
                            "path": entry.path,
                            "timestamp": str(entry.timestamp) if entry.timestamp else None,
                        }
                    )
            except Exception:
                # Try direct key lookup
                result_data.append({"path": key, "info": str(hive.get_key(key))})

        return RegistryResult(
            success=True,
            key_count=len(result_data),
            data=result_data,
        )
    except ImportError:
        # Fallback to reglookup CLI
        try:
            cmd = ["/usr/bin/reglookup", hive_path]
            if key and key != "/":
                cmd.extend(["-k", key])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            entries = []
            for line in result.stdout.strip().split("\n"):
                if line.strip() and not line.startswith("#"):
                    parts = line.split("|")
                    if len(parts) >= 3:
                        entries.append(
                            {
                                "path": parts[0],
                                "type": parts[1],
                                "value": parts[2] if len(parts) > 2 else "",
                            }
                        )
            return RegistryResult(
                success=result.returncode == 0,
                key_count=len(entries),
                data=entries[:500],
            )
        except FileNotFoundError:
            return RegistryResult(
                success=False,
                error="Neither regipy nor reglookup available. Install: pip install regipy",
            )
        except Exception as e:
            return RegistryResult(success=False, error=str(e))
    except Exception as e:
        return RegistryResult(success=False, error=str(e))


def analyze_hive_summary(hive_path: str) -> RegistryResult:
    """Get a summary of a registry hive structure."""
    try:
        from regipy import RegistryHive

        hive = RegistryHive(hive_path)

        top_keys = []
        for key in hive.root.iter_subkeys():
            try:
                top_keys.append(
                    {
                        "name": key.name,
                        "timestamp": str(key.timestamp) if key.timestamp else None,
                        "subkey_count": key.subkey_count,
                        "value_count": len(key.values) if hasattr(key, "values") else 0,
                    }
                )
            except Exception:
                top_keys.append({"name": key.name})

        return RegistryResult(
            success=True,
            key_count=len(top_keys),
            data=top_keys,
        )
    except ImportError:
        return RegistryResult(success=False, error="regipy not installed")
    except Exception as e:
        return RegistryResult(success=False, error=str(e))
