"""
Shared Pydantic data models for forensic analysis results.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class FileSystemEntry(BaseModel):
    """A file or directory entry from a forensic image."""

    name: str
    inode: Optional[int] = None
    file_type: str = Field(description="File type: file, directory, link, etc.")
    size: Optional[int] = None
    permissions: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    atime: Optional[str] = None
    mtime: Optional[str] = None
    ctime: Optional[str] = None
    crtime: Optional[str] = None


class Finding(BaseModel):
    """A forensic finding with traceability information."""

    id: str = Field(description="Unique finding identifier")
    description: str
    confidence: str = Field(description="CONFIRMED, INFERRED, or UNVERIFIED")
    artifact_type: str
    tool_used: str
    tool_arguments: dict = {}
    raw_output_snippet: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    iteration: int = 0
    source_evidence: str = ""


class ToolExecution(BaseModel):
    """Record of a single tool execution for audit trail."""

    tool: str
    arguments: dict = {}
    success: bool
    duration_ms: int
    error: Optional[str] = None
    output_summary: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class AuditReport(BaseModel):
    """Complete audit trail for submission."""

    session_id: str
    tool_executions: List[ToolExecution] = []
    findings: List[Finding] = []
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    total_duration_ms: int = 0
