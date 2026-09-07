"""Streaming JSONL output for real-time agent consumption.

UNIQUE feature: Agents can subscribe to a stream of findings
as they're discovered, instead of waiting for scan completion.
"""
import json
import sys
import time
from pathlib import Path
from typing import Optional, Callable


class StreamOutput:
    """Stream findings and events as JSONL for agent consumption.
    
    Output format (one JSON object per line):
        {"type": "finding", "data": {...}}
        {"type": "progress", "phase": "...", "progress": 0.5}
        {"type": "phase_start", "phase": "..."}
        {"type": "phase_end", "phase": "...", "elapsed": 1.2}
        {"type": "scan_start", "target": "...", "scan_id": "..."}
        {"type": "scan_end", "elapsed": 120, "findings": 5}
    """

    def __init__(self, output_file: str = None, stdout: bool = False,
                 callback: Callable = None):
        """
        Args:
            output_file: Path to JSONL file
            stdout: Also print to stdout
            callback: Function called with each event dict
        """
        self.output_file = Path(output_file) if output_file else None
        self.stdout = stdout
        self.callback = callback
        self._fh = None
        self._findings_count = 0

        if self.output_file:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.output_file, "w")

    def emit(self, event_type: str, data: dict = None):
        """Emit an event to the stream."""
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data or {}
        }

        line = json.dumps(event, default=str)

        if self._fh and not getattr(self._fh, "closed", False):
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
            except Exception:
                pass

        if self.stdout:
            print(line, file=sys.stdout)

        if self.callback:
            try:
                self.callback(event)
            except Exception:
                pass

    def finding(self, finding_type: str, severity: str, url: str,
                evidence: str = "", plugin: str = "", confidence: int = 0):
        """Emit a finding event."""
        self._findings_count += 1
        self.emit("finding", {
            "finding_type": finding_type,
            "severity": severity,
            "url": url,
            "evidence": evidence[:500],
            "plugin": plugin,
            "confidence": confidence,
            "finding_number": self._findings_count,
        })

    def progress(self, phase: str, current: int, total: int):
        """Emit a progress event."""
        pct = (current / total * 100) if total > 0 else 0
        self.emit("progress", {
            "phase": phase,
            "current": current,
            "total": total,
            "percent": round(pct, 1),
        })

    def phase_start(self, phase: str, description: str = ""):
        """Emit phase start event."""
        self.emit("phase_start", {
            "phase": phase,
            "description": description,
        })

    def phase_end(self, phase: str, elapsed: float, findings: int = 0):
        """Emit phase end event."""
        self.emit("phase_end", {
            "phase": phase,
            "elapsed": round(elapsed, 2),
            "findings": findings,
        })

    def scan_start(self, target: str, scan_id: str, phases: list[str]):
        """Emit scan start event."""
        self.emit("scan_start", {
            "target": target,
            "scan_id": scan_id,
            "phases": phases,
        })

    def scan_end(self, elapsed: float, total_findings: int, summary: dict):
        """Emit scan end event."""
        self.emit("scan_end", {
            "elapsed": round(elapsed, 2),
            "total_findings": total_findings,
            "summary": summary,
        })

    def error(self, phase: str, error: str):
        """Emit error event."""
        self.emit("error", {
            "phase": phase,
            "error": error,
        })

    def close(self):
        """Close the stream."""
        if self._fh:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass
            finally:
                self._fh = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
