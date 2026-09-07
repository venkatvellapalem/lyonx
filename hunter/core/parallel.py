"""Parallel plugin execution — run independent plugins concurrently.

UNIQUE feature: Adaptive parallel execution.
Plugins with no interdependencies run in parallel.
Plugins with dependencies wait for their prerequisites.
"""
import concurrent.futures
import time
from typing import Optional


class ParallelExecutor:
    """Execute independent plugins in parallel for speed.
    
    Analysis:
        - recon.subdomains, intel.waf_detect can run in parallel (no deps)
        - recon.dns waits for recon.subdomains
        - vuln.nuclei, vuln.cors can run in parallel (both need http_probe)
        - vuln.sqli, vuln.xss can run in parallel (both need param_mining)
    """

    # Groups of plugins that can run in parallel (no deps between them)
    PARALLEL_GROUPS = [
        # Group 1: Initial recon
        ["recon.subdomains"],
        # Group 2: DNS + intel on subdomains
        ["recon.dns", "intel.waf_detect"],
        # Group 3: Probe + ports
        ["recon.http_probe", "recon.ports"],
        # Group 4: URL discovery + tech detect
        ["recon.url_discovery", "intel.tech_detect"],
        # Group 5: JS + params + secrets + takeover
        ["recon.js_analysis", "recon.param_mining", "intel.secrets", "intel.takeover"],
        # Group 6: All vuln scans (can run in parallel)
        ["vuln.nuclei", "vuln.sqli", "vuln.xss", "vuln.cors", "vuln.redirects", "vuln.headers", "vuln.fuzz"],
        # Group 7: Post-processing
        ["post.prioritize", "post.report"],
    ]

    @classmethod
    def get_execution_plan(cls, available_plugins: list[str], skip: set[str] = None) -> list[list[str]]:
        """Get parallel execution plan.
        
        Returns list of groups. Each group runs in parallel.
        Groups execute sequentially (group N must finish before group N+1).
        """
        skip = skip or set()
        plan = []
        for group in cls.PARALLEL_GROUPS:
            active = [p for p in group if p in available_plugins and p not in skip]
            if active:
                plan.append(active)
        return plan

    @classmethod
    def execute_group(cls, plugins: list, budget, max_workers: int = 4) -> list:
        """Execute a group of plugins in parallel.
        
        Args:
            plugins: List of instantiated Plugin objects
            budget: Resource budget
            max_workers: Max concurrent plugins
            
        Returns:
            List of (plugin_name, success, elapsed) tuples
        """
        results = []

        def run_plugin(plugin):
            start = time.time()
            try:
                plugin.run(budget)
                elapsed = time.time() - start
                return (plugin.name, True, elapsed)
            except Exception as e:
                elapsed = time.time() - start
                return (plugin.name, False, elapsed)

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(plugins))) as executor:
            futures = {executor.submit(run_plugin, p): p.name for p in plugins}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)

        return results
