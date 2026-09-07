"""Main scanner engine — orchestrates adaptive scan pipeline."""
import time
import signal
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

from .state import ScanState, Finding
from .config import Config
from .dedup import Deduplicator
from .resource import ResourceManager
from .router import Router
from .incremental import IncrementalScanner
from .confidence import ConfidenceScorer
from .parallel import ParallelExecutor
from .stream import StreamOutput
from ..plugins import load_plugins, Plugin


class Scanner:
    """Agent-grade bug bounty scanner with adaptive routing.
    
    Features:
        - Adaptive routing: only runs relevant phases
        - State/resume: SQLite-backed, resume interrupted scans
        - Parallel execution: independent phases run concurrently
        - Incremental scanning: only scans new findings
        - Confidence scoring: reduce false positives
        - Streaming output: JSONL for real-time agent consumption
        - Resource budget: auto-throttle based on system load
    
    Usage:
        from hunter import Scanner
        s = Scanner("example.com")
        results = s.scan()
        
        # Agent API
        from hunter.agent.api import HunterAgent
        agent = HunterAgent()
        results = agent.scan("example.com")
    """

    def __init__(self, target: str, config: Config = None, scan_id: str = None,
                 output_dir: str = None, resume: bool = False):
        self.target = target.strip().lower()
        self.config = config or Config()
        
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_id = scan_id or f"{self.target}_{ts}"
        
        self.output_dir = Path(output_dir or Path.home() / "Hunter" / "results" / self.target / self.scan_id)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Core components
        self.state = ScanState(self.scan_id, str(self.output_dir))
        self.dedup = Deduplicator()
        self.resource = ResourceManager(self.config)
        self.router = Router(skip_phases=self.config.skip_phases)
        
        # NEW features
        self.incremental = IncrementalScanner(self.target)
        self.scorer = ConfidenceScorer()
        self.stream = StreamOutput(
            output_file=str(self.output_dir / "stream.jsonl"),
            stdout=False
        )
        
        # Load plugins
        self._plugin_classes = load_plugins()
        self._running = False
        self._start_time = None
        
        if not resume:
            self.state.init_scan(self.target, self.config.to_dict())
        
        signal.signal(signal.SIGINT, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        """Graceful interrupt — save state for resume."""
        print("\n  [!] Interrupted. Saving state for resume...")
        self.state.interrupt_scan()
        self._running = False
        self.stream.error("scan", "Interrupted by user")
        print(f"  [!] Use 'hunter resume {self.scan_id}' to continue.")
        sys.exit(0)

    def scan(self, phases: list[str] = None, resume: bool = False,
             incremental: bool = False, parallel: bool = True) -> ScanState:
        """Run the adaptive scan pipeline.
        
        Args:
            phases: Specific phases to run (None = adaptive)
            resume: Skip already-completed phases
            incremental: Only scan new findings (vs previous scan)
            parallel: Run independent phases concurrently
            
        Returns:
            ScanState with all findings
        """
        self._start_time = time.time()
        self._running = True
        
        available = self.resource.get_available_tools()
        missing = [t for t, ok in available.items() if not ok]
        
        print(f"\n  [hunter] Target: {self.target}")
        print(f"  [hunter] Scan ID: {self.scan_id}")
        print(f"  [hunter] Output: {self.output_dir}")
        if missing:
            print(f"  [!] Missing tools: {', '.join(missing[:5])}...")
        
        # Get execution plan
        all_plugins = list(self._plugin_classes.keys())
        
        if phases:
            self.router.only_phases = set(phases)
        
        if parallel:
            plan = ParallelExecutor.get_execution_plan(all_plugins, set(self.config.skip_phases))
            order = [p for group in plan for p in group]
        else:
            order = self.router.get_execution_order(self.state, all_plugins)
            plan = [[p] for p in order]
        
        completed = self.state.get_completed_phases()
        if resume:
            plan = [[p for p in group if p not in completed] for group in plan]
            plan = [g for g in plan if g]
        
        total_phases = sum(len(g) for g in plan)
        print(f"  [hunter] Plan: {total_phases} phases in {len(plan)} groups")
        self.stream.scan_start(self.target, self.scan_id, order)
        
        # Execute phase groups
        phase_num = 0
        for group in plan:
            if not self._running:
                break
            
            # Get plugins for this group
            plugins = []
            for plugin_name in group:
                plugin_cls = self._plugin_classes.get(plugin_name)
                if not plugin_cls:
                    continue
                cond = self.router.CONDITIONS.get(plugin_name)
                if cond and not cond(self.state):
                    continue
                if not self._check_plugin_tools(plugin_cls):
                    continue
                try:
                    plugin = plugin_cls(self.config, self.state, self.dedup, self.resource)
                    if plugin.should_run():
                        plugins.append(plugin)
                except Exception as e:
                    print(f"    ✗ Init error {plugin_name}: {e}")
            
            if not plugins:
                continue
            
            budget = self.resource.get_budget()
            
            if len(plugins) == 1:
                # Single plugin — run directly
                plugin = plugins[0]
                phase_num += 1
                print(f"  [{phase_num}/{total_phases}] ▶ {plugin.name}: {plugin.description}")
                self.stream.phase_start(plugin.name, plugin.description)
                
                start = time.time()
                try:
                    plugin.run(budget)
                    elapsed = time.time() - start
                    self.state.mark_phase_complete(plugin.name)
                    self.stream.phase_end(plugin.name, elapsed, len(self.state.get_findings()))
                    print(f"    ✓ {elapsed:.1f}s | Findings: {len(self.state.get_findings())}")
                except Exception as e:
                    print(f"    ✗ Error: {e}")
                    self.stream.error(plugin.name, str(e))
            else:
                # Multiple plugins — run in parallel
                phase_num += len(plugins)
                names = ", ".join(p.name for p in plugins)
                print(f"  [{phase_num}/{total_phases}] ▶ Parallel: {names}")
                
                for p in plugins:
                    self.stream.phase_start(p.name, p.description)
                
                start = time.time()
                results = ParallelExecutor.execute_group(plugins, budget, max_workers=budget.max_concurrent_tools)
                elapsed = time.time() - start
                
                for name, success, plugin_elapsed in results:
                    if success:
                        self.state.mark_phase_complete(name)
                        self.stream.phase_end(name, plugin_elapsed, len(self.state.get_findings()))
                    else:
                        self.stream.error(name, "Failed")
                
                print(f"    ✓ Parallel done in {elapsed:.1f}s | Findings: {len(self.state.get_findings())}")
        
        # Update incremental history
        self.incremental.update_history(self.scan_id, {
            "subdomains": self.state.get_state("recon.subdomains", "subdomains", []),
            "urls": self.state.get_state("recon.url_discovery", "all_urls", []),
        })
        
        # Finalize
        self.state.complete_scan()
        self._running = False
        elapsed = time.time() - self._start_time
        
        summary = self.state.summary()
        self.stream.scan_end(elapsed, summary["total_findings"], summary)
        
        print(f"\n  [hunter] Done in {elapsed:.0f}s")
        print(f"  [hunter] Findings: {summary['total_findings']}")
        for sev, cnt in summary['findings'].items():
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev, "⚪")
            print(f"    {icon} {sev}: {cnt}")
        print(f"  [hunter] Report: {self.output_dir}/report.md")
        print(f"  [hunter] Stream: {self.output_dir}/stream.jsonl")
        
        self.stream.close()
        return self.state

    def resume(self) -> ScanState:
        """Resume an interrupted scan."""
        return self.scan(resume=True)

    def _check_plugin_tools(self, plugin_cls) -> bool:
        required = getattr(plugin_cls, 'required_tools', [])
        if not required:
            return True
        return all(self.resource.check_tool_available(t) for t in required)

    def close(self):
        """Cleanly close scanner resources."""
        if hasattr(self, "stream") and self.stream:
            try:
                self.stream.close()
            except Exception:
                pass
        if hasattr(self, "state") and self.state:
            try:
                self.state.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def summary(self) -> dict:
        return self.state.summary()

    def findings(self, severity: str = None, finding_type: str = None):
        return self.state.get_findings(severity=severity, finding_type=finding_type)

    @staticmethod
    def resume_scan(scan_id: str, base_dir: str = None) -> "Scanner":
        if base_dir:
            output_dir = Path(base_dir)
        else:
            results_dir = Path.home() / "Hunter" / "results"
            matches = list(results_dir.rglob(f"*/{scan_id}"))
            if not matches:
                raise FileNotFoundError(f"Scan {scan_id} not found")
            output_dir = matches[0]
        
        state = ScanState(scan_id, str(output_dir))
        summary = state.summary()
        state.close()
        
        return Scanner(
            target=summary["target"],
            config=Config(),
            scan_id=scan_id,
            output_dir=str(output_dir),
            resume=True
        )
