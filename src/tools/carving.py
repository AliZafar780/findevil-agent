"""
File Carving and Feature Extraction Tools
Wraps foremost, bulk_extractor, and binwalk.
"""
import subprocess
import json
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


class CarvingResult(BaseModel):
    success: bool = True
    data: list = []
    error: Optional[str] = None
    file_count: int = 0
    output_dir: Optional[str] = None


def carve_files(image_path: str, file_types: str = "all", output_dir: Optional[str] = None) -> CarvingResult:
    """Carve deleted files from disk image based on headers using foremost."""
    try:
        if output_dir is None:
            output_dir = f"/results/carved/{Path(image_path).stem}"
        Path(output_dir).parent.mkdir(parents=True, exist_ok=True)

        cmd = ["/usr/bin/foremost", "-o", output_dir, "-q"]
        if file_types and file_types != "all":
            cmd.extend(["-t", file_types])
        cmd.append(image_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        # Count carved files
        carved_files = []
        if Path(output_dir).exists():
            for f in Path(output_dir).rglob("*"):
                if f.is_file() and f.stat().st_size > 0:
                    carved_files.append({
                        "path": str(f),
                        "size": f.stat().st_size,
                        "name": f.name,
                    })

        if not result.returncode == 0 and not result.stdout:
            return CarvingResult(
                success=False,
                error=result.stderr[:2000] or result.stdout[:2000],
            )

        return CarvingResult(
            success=True,
            output_dir=output_dir,
            file_count=len(carved_files),
            data=carved_files[:500],
        )
    except subprocess.TimeoutExpired:
        return CarvingResult(success=False, error="foremost timed out after 600s")
    except FileNotFoundError:
        return CarvingResult(success=False, error="foremost not found at /usr/bin/foremost")
    except Exception as e:
        return CarvingResult(success=False, error=str(e))


def extract_features(image_path: str, scanners: str = "all") -> CarvingResult:
    """Extract emails, URLs, credit cards, and other features using bulk_extractor."""
    try:
        output_dir = f"/results/carved/{Path(image_path).stem}_features"
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        cmd = ["/usr/bin/bulk_extractor", "-o", output_dir, "-q"]
        if scanners and scanners != "all":
            for s in scanners.split(","):
                cmd.extend(["-S", s.strip()])
        cmd.append(image_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        # Collect feature files
        feature_files = {}
        if Path(output_dir).exists():
            for f in sorted(Path(output_dir).glob("*.txt")):
                if f.stat().st_size > 0:
                    try:
                        lines = f.read_text(errors="replace").split("\n")
                        # Filter out comment/header lines
                        data_lines = [l for l in lines if l.strip() and not l.startswith("#")]
                        feature_files[f.name] = {
                            "path": str(f),
                            "size": f.stat().st_size,
                            "count": len(data_lines),
                            "samples": data_lines[:20],
                        }
                    except Exception:
                        feature_files[f.name] = {"path": str(f), "size": f.stat().st_size}

        return CarvingResult(
            success=True,
            output_dir=output_dir,
            file_count=len(feature_files),
            data=[{"feature_files": feature_files, "raw_output": result.stdout[:5000]}],
        )
    except FileNotFoundError:
        return CarvingResult(
            success=False,
            error="bulk_extractor not found. Install: sudo apt-get install bulk-extractor",
        )
    except subprocess.TimeoutExpired:
        return CarvingResult(success=False, error="bulk_extractor timed out after 600s")
    except Exception as e:
        return CarvingResult(success=False, error=str(e))


def analyze_binary(image_path: str) -> CarvingResult:
    """Analyze binary file structure using binwalk."""
    try:
        cmd = ["/usr/bin/binwalk", "-B", "-M", image_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        entries = []
        for line in result.stdout.strip().split("\n"):
            if line.strip() and not line.startswith("#") and not line.startswith("DECIMAL"):
                parts = line.split(maxsplit=3)
                if len(parts) >= 3:
                    try:
                        entries.append({
                            "offset": int(parts[0]),
                            "description": parts[-1] if len(parts) > 1 else "",
                        })
                    except ValueError:
                        continue

        return CarvingResult(
            success=result.returncode == 0,
            data=[{"entries": entries[:200], "raw_output": result.stdout[:10000]}],
        )
    except FileNotFoundError:
        return CarvingResult(success=False, error="binwalk not found")
    except Exception as e:
        return CarvingResult(success=False, error=str(e))
