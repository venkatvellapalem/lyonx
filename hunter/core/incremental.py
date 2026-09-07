"""Incremental scanning — only scan what changed since last run.

This is UNIQUE to Hunter. No other tool does this.
Compares current scan with previous scan's artifacts.
Only runs phases on NEW findings (new subdomains, new URLs, etc.)
"""
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional


class IncrementalScanner:
    """Track changes between scans for efficient re-scanning.
    
    Usage:
        scanner = Scanner("example.com")
        state = scanner.scan(incremental=True)  # Only scans new stuff
    """

    def __init__(self, target: str, results_dir: str = None):
        self.target = target
        self.results_dir = Path(results_dir or Path.home() / "Hunter" / "results" / target)
        self.history_file = self.results_dir / ".scan_history.json"
        self._history = self._load_history()

    def _load_history(self) -> dict:
        """Load scan history."""
        if self.history_file.exists():
            try:
                return json.loads(self.history_file.read_text())
            except Exception:
                pass
        return {"scans": [], "last_scan": None, "known_subdomains": [], "known_urls": []}

    def _save_history(self):
        """Save scan history."""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        self.history_file.write_text(json.dumps(self._history, indent=2))

    def get_last_scan(self) -> Optional[dict]:
        """Get the last completed scan info."""
        if self._history.get("scans"):
            return self._history["scans"][-1]
        return None

    def get_known_artifacts(self) -> dict:
        """Get known artifacts from previous scans."""
        return {
            "subdomains": set(self._history.get("known_subdomains", [])),
            "urls": set(self._history.get("known_urls", [])),
        }

    def find_new_items(self, current_items: list[str], artifact_type: str) -> list[str]:
        """Find items that are NEW compared to previous scans.
        
        Returns only items not seen in any previous scan.
        """
        known_key = f"known_{artifact_type}"
        known = set(self._history.get(known_key, []))
        new_items = [item for item in current_items if item not in known]
        return new_items

    def update_history(self, scan_id: str, artifacts: dict):
        """Update history with new scan results.
        
        Args:
            scan_id: The scan ID
            artifacts: Dict of artifact_type -> list of items
        """
        # Add scan record
        self._history.setdefault("scans", []).append({
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "subdomains_count": len(artifacts.get("subdomains", [])),
            "urls_count": len(artifacts.get("urls", [])),
        })

        # Keep only last 10 scans
        self._history["scans"] = self._history["scans"][-10:]
        self._history["last_scan"] = scan_id

        # Update known artifacts (accumulate across scans)
        for artifact_type, items in artifacts.items():
            known_key = f"known_{artifact_type}"
            existing = set(self._history.get(known_key, []))
            existing.update(items)
            self._history[known_key] = sorted(existing)

        self._save_history()

    def should_rescan(self, interval_hours: int = 24) -> bool:
        """Check if enough time has passed to warrant a rescan."""
        last = self.get_last_scan()
        if not last:
            return True
        last_time = datetime.fromisoformat(last["timestamp"])
        elapsed = (datetime.now() - last_time).total_seconds() / 3600
        return elapsed >= interval_hours

    def get_diff_summary(self, current_subdomains: list[str], current_urls: list[str]) -> dict:
        """Get a summary of what changed since last scan."""
        known = self.get_known_artifacts()
        new_subs = set(current_subdomains) - known["subdomains"]
        new_urls = set(current_urls) - known["urls"]
        gone_subs = known["subdomains"] - set(current_subdomains)

        return {
            "new_subdomains": sorted(new_subs),
            "new_urls": sorted(new_urls),
            "gone_subdomains": sorted(gone_subs),
            "total_new": len(new_subs) + len(new_urls),
        }
