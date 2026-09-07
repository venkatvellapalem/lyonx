"""Resource budget management — auto-throttle based on system load."""
import os
import subprocess
from dataclasses import dataclass


@dataclass
class Budget:
    """Resource budget for scan operations."""
    threads: int = 25
    delay: float = 0.0
    max_concurrent_tools: int = 3

    @property
    def is_conservative(self) -> bool:
        return self.threads <= 10


class ResourceManager:
    """Monitors system resources and adjusts scan parameters."""

    def __init__(self, config):
        self.config = config
        self._psutil = None
        try:
            import psutil
            self._psutil = psutil
        except ImportError:
            pass

    def get_budget(self) -> Budget:
        """Get current resource budget based on system state."""
        if self.config.resource_budget == "aggressive":
            return Budget(threads=self.config.threads, delay=0, max_concurrent_tools=5)
        elif self.config.resource_budget == "conservative":
            return Budget(threads=max(5, self.config.threads // 3), delay=0.5, max_concurrent_tools=1)
        elif self.config.resource_budget == "minimal":
            return Budget(threads=5, delay=1.0, max_concurrent_tools=1)

        # Auto mode — detect system state
        return self._auto_budget()

    def _auto_budget(self) -> Budget:
        """Automatically determine budget from system resources."""
        if not self._psutil:
            return Budget(threads=self.config.threads, delay=0)

        ram = self._psutil.virtual_memory()
        cpu = self._psutil.cpu_percent(interval=0.5)
        threads = self.config.threads

        if ram.percent > 85 or cpu > 90:
            # System under stress
            return Budget(
                threads=max(5, threads // 4),
                delay=1.0,
                max_concurrent_tools=1
            )
        elif ram.percent > 70 or cpu > 70:
            # Moderate load
            return Budget(
                threads=max(10, threads // 2),
                delay=0.2,
                max_concurrent_tools=2
            )
        else:
            # System has headroom
            return Budget(threads=threads, delay=0, max_concurrent_tools=3)

    def check_tool_available(self, tool: str) -> bool:
        """Check if a tool binary exists in PATH."""
        try:
            result = subprocess.run(
                ["which", tool],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def get_available_tools(self) -> dict[str, bool]:
        """Check availability of all required tools."""
        tools = [
            "subfinder", "assetfinder", "alterx", "shuffledns", "asnmap",
            "dnsx", "puredns", "massdns",
            "httpx", "httprobe", "tlsx",
            "naabu", "rustscan", "nmap",
            "katana", "gau", "waybackurls",
            "ffuf",
            "nuclei", "dalfox", "sqlmap",
            "gitleaks", "trufflehog",
            "arjun", "uncover", "mapcidr",
            "notify", "proxify", "anew", "unfurl",
            "interactsh-client"
        ]
        return {t: self.check_tool_available(t) for t in tools}
