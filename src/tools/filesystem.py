"""
File System Analysis Tools
Wraps TSK (The Sleuth Kit) commands via subprocess.
"""
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field


class Partition(BaseModel):
    slot: int = Field(..., description="Partition slot number")
    start: int = Field(..., description="Start sector")
    end: int = Field(..., description="End sector")
    length: int = Field(..., description="Length in sectors")
    description: str = Field(..., description="Partition type description")


class FileEntry(BaseModel):
    name: str = Field(..., description="File or directory name")
    inode: Optional[int] = Field(None, description="Inode number")
    file_type: str = Field("?", description="File type")
    size: Optional[int] = Field(None, description="File size in bytes")
    meta_flags: Optional[str] = Field(None, description="Metadata flags")


class InodeInfo(BaseModel):
    inode: int
    mode: str
    uid: int
    gid: int
    size: int
    atime: str
    mtime: str
    ctime: str
    crtime: str
    num_links: int


class FsStats(BaseModel):
    fs_type: str = ""
    block_size: int = 0
    block_count: int = 0
    volume_name: Optional[str] = None
    details: str = ""


class FileSystemResult(BaseModel):
    success: bool = True
    data: list = []
    error: Optional[str] = None


SLEUTHKIT_BIN = "/usr/bin"


def _run_tsk(tool: str, args: List[str], timeout: int = 120) -> str:
    """Run a TSK tool and return stdout."""
    cmd = [f"{SLEUTHKIT_BIN}/{tool}"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            raise RuntimeError(f"{tool} failed: {result.stderr[:2000]}")
        return result.stdout
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"{tool} timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError(f"{tool} not found at {SLEUTHKIT_BIN}/{tool}")


def list_files(image_path: str, offset: int = 0, inode: Optional[int] = None, recursive: bool = False) -> FileSystemResult:
    """List files using fls."""
    try:
        args = []
        if recursive:
            args.append("-r")
        if offset:
            args.extend(["-o", str(offset)])
        args.append(image_path)
        if inode is not None:
            args.append(str(inode))

        output = _run_tsk("fls", args)
        entries = []
        for line in output.strip().split("\n"):
            if line.strip():
                parts = line.split(maxsplit=3) if len(line) > 3 else line.split()
                entry = {
                    "raw": line,
                    "name": line.rsplit(" ", 1)[-1] if " " in line else line,
                }
                if len(parts) >= 2:
                    entry["type_flag"] = parts[0]
                entries.append(entry)
        return FileSystemResult(data=entries)
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))


def extract_file(image_path: str, inode: int, offset: int = 0, output_path: Optional[str] = None) -> FileSystemResult:
    """Extract file using icat."""
    try:
        args = []
        if offset:
            args.extend(["-o", str(offset)])
        args.extend([image_path, str(inode)])
        data = _run_tsk("icat", args)

        result_data = {"inode": inode, "size": len(data)}
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(data.encode("latin-1"))
            result_data["extracted_to"] = output_path
        else:
            result_data["preview"] = data[:5000]
            result_data["preview_truncated"] = len(data) > 5000

        return FileSystemResult(data=[result_data])
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))


def scan_partitions(image_path: str) -> FileSystemResult:
    """Scan partitions using mmls."""
    try:
        output = _run_tsk("mmls", [image_path])
        partitions = []
        for line in output.strip().split("\n"):
            stripped = line.strip()
            if stripped and (stripped[0].isdigit() or "Meta" in stripped or "Unallocated" in stripped or "GPT" in stripped):
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        slot_str = parts[0].rstrip(":")
                        if slot_str.isdigit():
                            partitions.append(Partition(
                                slot=int(slot_str),
                                start=int(parts[2]),
                                end=int(parts[3]),
                                length=int(parts[4]),
                                description=" ".join(parts[5:]),
                            ).model_dump())
                    except (ValueError, IndexError):
                        continue
        return FileSystemResult(data=partitions)
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))


def get_fs_stats(image_path: str, offset: int = 0) -> FileSystemResult:
    """Get file system stats using fsstat."""
    try:
        args = ["-o", str(offset), image_path] if offset else [image_path]
        output = _run_tsk("fsstat", args)
        return FileSystemResult(data=[{"raw_output": output[:10000]}])
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))


def get_inode_metadata(image_path: str, inode: int, offset: int = 0) -> FileSystemResult:
    """Get inode metadata using istat."""
    try:
        args = []
        if offset:
            args.extend(["-o", str(offset)])
        args.extend([image_path, str(inode)])
        output = _run_tsk("istat", args)
        return FileSystemResult(data=[{"raw_output": output[:10000]}])
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))


def extract_strings(image_path: str, min_length: int = 6) -> FileSystemResult:
    """Extract strings from a binary file."""
    try:
        result = subprocess.run(
            ["/usr/bin/strings", "-n", str(min_length), image_path],
            capture_output=True, text=True, timeout=120
        )
        strings_list = [s for s in result.stdout.strip().split("\n") if s.strip()]
        return FileSystemResult(data=strings_list[:5000])
    except Exception as e:
        return FileSystemResult(success=False, error=str(e))
