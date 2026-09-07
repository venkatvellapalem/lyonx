"""Agent API — programmatic interface for AI agents."""
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional, Callable

from ..core.scanner import Scanner
from ..core.config import Config
from ..core.state import Finding
from ..core.token_efficient import TokenEfficient
from ..core.agent_engine import AttackPlan
from ..core.payloads import Payloads


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

    def to_json(self, compact: bool = False) -> str:
        if compact:
            return TokenEfficient.compact_json(asdict(self))
        return json.dumps(asdict(self), indent=2, default=str)

    def to_one_line(self) -> str:
        return TokenEfficient.one_line_summary_from_dict(self.summary)

    def critical_findings(self) -> list[dict]:
        return [f for f in self.findings if f.get("severity") == "critical"]

    def high_findings(self) -> list[dict]:
        return [f for f in self.findings if f.get("severity") == "high"]

    def has_vulnerabilities(self) -> bool:
        return any(f.get("severity") in ("critical", "high") for f in self.findings)

    def action_items(self) -> list[str]:
        """Get pre-computed action items for the agent."""
        return TokenEfficient.action_items_from_findings(self.findings)


class HunterAgent:
    """Programmatic interface for AI agents to run scans.
    
    Features:
        - Token-efficient output (compact JSON, one-line summaries)
        - Pre-built attack plans (no LLM calls for payloads)
        - Pre-computed action items (agents just execute)
        - Delta reports (only new findings)
    
    Example:
        agent = HunterAgent()
        
        # Full scan
        results = agent.scan("example.com")
        
        # Token-efficient output
        print(results.to_json(compact=True))  # Minimal tokens
        print(results.to_one_line())  # Single line
        
        # Get action items (pre-computed, no LLM needed)
        for action in results.action_items():
            print(action)  # "TEST sqli https://..."
        
        # Get attack plan (pre-built payloads)
        plan = agent.get_attack_plan("example.com")
        for step in plan:
            print(step)  # Pre-computed attack step
    """

    def __init__(self, config: Config = None):
        self.config = config or Config()

    def scan(self, target: str, threads: int = None, aggressive: bool = None,
             phases: list[str] = None, skip: list[str] = None,
             output_dir: str = None) -> ScanResults:
        """Run a scan and return results."""
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

        summary = state.summary()
        findings = [asdict(f) for f in state.get_findings()]

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

    def get_attack_plan(self, target: str) -> list[dict]:
        """Get pre-computed attack plan for a target.
        
        Returns list of attack steps with pre-built payloads.
        Agents execute these directly — no LLM calls needed.
        """
        # Run recon first to discover surface
        results = self.scan(target, phases=[
            "recon.subdomains", "recon.dns", "recon.http_probe",
            "recon.url_discovery", "recon.param_mining",
            "intel.tech_detect", "intel.secrets"
        ])

        # Load state for attack planning
        scanner = Scanner(target, output_dir=results.output_dir)
        plan = AttackPlan(scanner.state, self.config)
        attack_steps = plan.generate_plan()
        scanner.state.close()

        return attack_steps

    def execute_attack(self, target: str, step: dict) -> dict:
        """Execute a single attack step.
        
        Args:
            target: Domain
            step: Attack step from get_attack_plan()
            
        Returns:
            Result dict with vulnerability status and evidence
        """
        scanner = Scanner(target)
        plan = AttackPlan(scanner.state, self.config)
        result = plan.execute_step(step)
        scanner.state.close()
        return result

    def quick_recon(self, target: str) -> dict:
        """Quick recon-only scan."""
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
        """Quick vulnerability scan."""
        return self.scan(target, phases=[
            "recon.subdomains", "recon.dns", "recon.http_probe",
            "recon.url_discovery", "recon.param_mining",
            "vuln.nuclei", "vuln.sqli", "vuln.xss",
            "post.prioritize", "post.report"
        ])

    def payloads(self, vuln_type: str = None) -> dict:
        """Get pre-built payloads.
        
        Args:
            vuln_type: sqli, xss, ssrf, ssti, redirect, lfi, cmdi, etc.
                       None = return all types
        """
        if vuln_type:
            return {vuln_type: Payloads.get(vuln_type)}
        return {t: Payloads.get(t) for t in Payloads.all_types()}

    def compact_summary(self, target: str) -> str:
        """One-line summary for minimal token usage."""
        results = self.scan(target)
        return f"target={target} findings={len(results.findings)} critical={len(results.critical_findings())} high={len(results.high_findings())}"
