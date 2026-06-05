"""
Timeline Analysis Tools
Wraps log2timeline/plaso via subprocess for forensic timeline generation.
"""

import json
import subprocess
from pathlib import Path
from typing import Optional

from pydantic import BaseModel


class TimelineResult(BaseModel):
    success: bool = True
    data: list = []
    error: Optional[str] = None
    storage_path: Optional[str] = None
    event_count: int = 0


def build(source_path: str, output_path: Optional[str] = None) -> TimelineResult:
    """Build forensic timeline using log2timeline/plaso."""
    try:
        if output_path is None:
            output_path = f"/results/timelines/{Path(source_path).stem}.plaso"
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        # Try plaso (log2timeline)
        cmd = ["log2timeline", "--quiet", "--storage_file", output_path, source_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            # Try log2timeline legacy
            cmd = ["log2timeline", "-f", "plaso", "-o", output_path, source_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        if result.returncode not in (0, 1):
            return TimelineResult(
                success=False,
                error=f"log2timeline failed: {result.stderr[:2000]}",
            )

        return TimelineResult(
            success=True,
            storage_path=output_path,
            data=[{"storage_path": output_path, "source": source_path}],
        )
    except subprocess.TimeoutExpired:
        return TimelineResult(success=False, error="Timeline build timed out after 600s")
    except FileNotFoundError as e:
        return TimelineResult(success=False, error=f"log2timeline not found: {e}")
    except Exception as e:
        return TimelineResult(success=False, error=str(e))


def filter_timeline(
    storage_path: str, query: str = "", output_format: str = "json"
) -> TimelineResult:
    """Filter and export a Plaso timeline using psort."""
    try:
        if output_format == "json":
            output_path = storage_path.replace(".plaso", "_filtered.json")
            cmd = [
                "psort",
                "-q",
                "-o",
                "json",
                "--output_file",
                output_path,
                storage_path,
            ]
            if query:
                cmd.extend(["--slice", query])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            events = []
            if Path(output_path).exists():
                with open(output_path) as f:
                    for line in f:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

            return TimelineResult(
                success=True,
                storage_path=output_path,
                event_count=len(events),
                data=events[:1000],
            )
        else:
            cmd = [
                "psort",
                "-q",
                "-o",
                "dynamic",
                "--output_file",
                storage_path.replace(".plaso", "_filtered.csv"),
                storage_path,
            ]
            if query:
                cmd.extend(["--slice", query])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            return TimelineResult(
                success=result.returncode == 0,
                event_count=0,
                data=[{"raw_output": result.stdout[:5000]}],
            )
    except subprocess.TimeoutExpired:
        return TimelineResult(success=False, error="Timeline filter timed out after 300s")
    except FileNotFoundError:
        return TimelineResult(
            success=False, error="psort not found. Install plaso: pip install plaso"
        )
    except Exception as e:
        return TimelineResult(success=False, error=str(e))
