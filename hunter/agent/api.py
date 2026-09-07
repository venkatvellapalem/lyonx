"""Agent API — programmatic interface for AI agents.

Usage:
    from hunter.agent.api import HunterAgent
    
    agent = HunterAgent()
    results = agent.scan("example.com")
    print(results.findings)
    print(results.summary)
"""
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional, Callable

from ..core.scanner import Scanner
from ..core.config import Config
from ..core.state import Finding


@dataclass
class ScanResults:
    """Results from a scan, formatted for agent consumption."""
    scan_id: str
    target: str
    status: str
    elapsed: float
    summary: dict
    findings: list[dict]
    manual_targets: str
    output_dir: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)

    def critical_findings(self) -> list[dict]:
        return [f for f in self.findings if f.get("severity") == "critical"]

    def high_findings(self) -> list[dict]:
        return [f for f in self.findings if f.get("severity") == "high"]

    def has_vulnerabilities(self) -> bool:
        return any(f.get("severity") in ("critical", "high") for f in self.findings)


class HunterAgent:
    """Programmatic interface for AI agents to run scans.
    
    Example:
        agent = HunterAgent()
        
        # Simple scan
        results = agent.scan("example.com")
        
        # Scan with options
        results = agent.scan("example.com", threads=30, aggressive=True)
        
        # Adaptive scan (engine decides what to run)
        results = agent.scan("example.com", mode="adaptive")
        
        # Specific phases
        results = agent.scan("example.com", phases=["recon.subdomains", "vuln.nuclei"])
        
        # Resume
        results = agent.resume("example.com_20260907_1234")
        
        # Access results
        if results.has_vulnerabilities():
            for f in results.critical_findings():
                print(f"CRITICAL: {f['type']} at {f['url']}")
    """

    def __init__(self, config: Config = None):
        self.config = config or Config()

    def scan(self, target: str, threads: int = None, aggressive: bool = None,
             phases: list[str] = None, skip: list[str] = None,
             mode: str = "adaptive", output_dir: str = None) -> ScanResults:
        """Run a scan and return results.
        
        Args:
            target: Domain to scan
            threads: Concurrency level
            aggressive: Enable aggressive mode
            phases: Specific phases to run
            skip: Phases to skip
            mode: "adaptive" (default) or "all"
            output_dir: Custom output directory
            
        Returns:
            ScanResults with findings and summary
        """
        config = Config.from_dict(self.config.to_dict())
        if threads:
            config.threads = threads
        if aggressive is not None:
            config.aggressive = aggressive
        if skip:
            config.skip_phases = skip

        scanner = Scanner(target, config=config, output_dir=output_dir)
        start = time.time()
        state = scanner.scan(phases=phases)
        elapsed = time.time() - start

        # Collect results
        summary = state.summary()
        findings = [asdict(f) for f in state.get_findings()]

        # Read manual targets if available
        manual_path = scanner.output_dir / "post" / "prioritize" / "manual_targets.md"
        manual_targets = ""
        if manual_path.exists():
            manual_targets = manual_path.read_text()

        state.close()

        return ScanResults(
            scan_id=scanner.scan_id,
            target=target,
            status="completed",
            elapsed=elapsed,
            summary=summary,
            findings=findings,
            manual_targets=manual_targets,
            output_dir=str(scanner.output_dir)
        )

    def resume(self, scan_id: str) -> ScanResults:
        """Resume an interrupted scan."""
        scanner = Scanner.resume_scan(scan_id)
        start = time.time()
        state = scanner.resume()
        elapsed = time.time() - start

        summary = state.summary()
        findings = [asdict(f) for f in state.get_findings()]
        state.close()

        return ScanResults(
            scan_id=scan_id,
            target=summary.get("target", ""),
            status="completed",
            elapsed=elapsed,
            summary=summary,
            findings=findings,
            manual_targets="",
            output_dir=str(scanner.output_dir)
        )

    def quick_recon(self, target: str) -> dict:
        """Quick recon-only scan (subdomains + live hosts + ports).
        
        Returns dict with subdomains, live_urls, ports.
        """
        results = self.scan(target, phases=[
            "recon.subdomains", "recon.dns", "recon.http_probe", "recon.ports"
        ])
        return {
            "subdomains": results.summary.get("subdomains", []),
            "live_urls": results.summary.get("live_urls", []),
            "ports": results.summary.get("ports", []),
            "elapsed": results.elapsed
        }

    def vuln_scan(self, target: str) -> ScanResults:
        """Quick vulnerability scan (assumes recon done, runs vuln phases)."""
        return self.scan(target, phases=[
            "recon.subdomains", "recon.dns", "recon.http_probe",
            "recon.url_discovery", "recon.param_mining",
            "vuln.nuclei", "vuln.sqli", "vuln.xss",
            "post.prioritize", "post.report"
        ])
