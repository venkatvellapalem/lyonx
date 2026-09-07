"""Smart routing — decides which plugins to run based on findings."""


class Router:
    """Adaptive router that selects plugins based on scan state."""

    # Dependency graph: plugin → list of phases it needs to have completed
    DEPENDENCIES = {
        "recon.subdomains": [],
        "recon.dns": ["recon.subdomains"],
        "recon.http_probe": ["recon.dns"],
        "recon.ports": ["recon.dns"],
        "recon.url_discovery": ["recon.http_probe"],
        "recon.js_analysis": ["recon.url_discovery"],
        "recon.param_mining": ["recon.url_discovery"],
        "recon.header_analysis": ["recon.http_probe"],
        "intel.tech_detect": ["recon.http_probe"],
        "intel.waf_detect": ["recon.http_probe"],
        "intel.cms_scan": ["recon.http_probe"],
        "intel.secrets": ["recon.url_discovery"],
        "intel.takeover": ["recon.dns"],
        "vuln.nuclei": ["recon.http_probe"],
        "vuln.sqli": ["recon.param_mining"],
        "vuln.xss": ["recon.param_mining"],
        "vuln.cors": ["recon.http_probe"],
        "vuln.redirects": ["recon.url_discovery"],
        "vuln.headers": ["recon.http_probe"],
        "vuln.graphql": ["recon.url_discovery"],
        "vuln.smuggler": ["recon.http_probe"],
        "vuln.ssti": ["recon.param_mining"],
        "vuln.ssrf": ["recon.param_mining"],
        "vuln.fuzz": ["recon.http_probe"],
        "post.prioritize": [],  # Always runs
        "post.report": [],      # Always runs
    }

    # Conditional routing: if state has X, run Y
    CONDITIONS = {
        "vuln.sqli": lambda s: len(s.get_state("recon.param_mining", "injectable_urls", [])) > 0,
        "vuln.xss": lambda s: len(s.get_state("recon.param_mining", "param_urls", [])) > 0,
        "vuln.graphql": lambda s: len(s.get_state("recon.url_discovery", "api_endpoints", [])) > 0 or
                                   any("graphql" in str(s.get_state("recon.url_discovery", "api_endpoints", [])).lower() for _ in [1]),
        "vuln.ssti": lambda s: len(s.get_state("recon.param_mining", "param_urls", [])) > 0,
        "vuln.ssrf": lambda s: len(s.get_state("recon.param_mining", "param_urls", [])) > 0,
        "intel.cms_scan": lambda s: s.get_state("intel.tech_detect", "cms") is not None,
        "intel.waf_detect": lambda s: True,  # Always useful
    }

    def __init__(self, skip_phases: list[str] = None, only_phases: list[str] = None):
        self.skip_phases = set(skip_phases or [])
        self.only_phases = set(only_phases) if only_phases else None

    def get_execution_order(self, state, all_plugins: list[str]) -> list[str]:
        """Determine which plugins to run and in what order.
        
        Args:
            state: Current ScanState
            all_plugins: List of all available plugin names
            
        Returns:
            Ordered list of plugin names to execute
        """
        completed = set(state.get_completed_phases())
        ordered = []

        # Topological sort based on dependencies
        remaining = set(all_plugins) - self.skip_phases
        if self.only_phases:
            remaining = remaining & self.only_phases

        max_iterations = len(remaining) + 1
        iteration = 0

        while remaining and iteration < max_iterations:
            iteration += 1
            progress = False

            for plugin in list(remaining):
                # Check if dependencies are met
                deps = self.DEPENDENCIES.get(plugin, [])
                if not all(d in completed or d in ordered for d in deps):
                    continue

                # Check conditional routing
                condition = self.CONDITIONS.get(plugin)
                if condition and not condition(state):
                    remaining.discard(plugin)
                    continue

                ordered.append(plugin)
                remaining.discard(plugin)
                progress = True

            if not progress:
                # Remaining plugins have unmet dependencies — skip them
                break

        return ordered

    def should_skip(self, plugin_name: str) -> bool:
        """Check if a plugin should be skipped."""
        return plugin_name in self.skip_phases
