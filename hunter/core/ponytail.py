"""Ponytail integration — makes agents think like lazy senior devs.

Token reduction via smart agent behavior, not output compression.

Principles (from ponytail):
1. Does this need to exist? (skip unnecessary phases)
2. Already in this codebase? (reuse previous scan data)
3. Can it be one line? (minimal tool calls)
4. Ship the lazy version (don't over-scan)

Result: Fewer tool calls = fewer tokens = faster scans.
"""
from typing import Optional


class PonytailAgent:
    """Agent behavior modifier — forces lazy, efficient thinking.
    
    Instead of running every scan phase, asks:
    - Do we already have this data? (skip if yes)
    - Is this phase relevant? (skip if no)
    - Can we combine multiple steps? (merge if yes)
    - What's the minimum we need? (run only that)
    """

    def __init__(self, state=None):
        self.state = state

    def should_run_phase(self, phase: str, context: dict = None) -> bool:
        """Decide if a phase needs to run. Ponytail: skip if unnecessary."""
        if not self.state:
            return True

        # Already completed? Skip.
        if self.state.is_phase_complete(phase):
            return False

        # No dependencies found? Skip.
        if phase == "vuln.sqli" and not self.state.get_state("recon.param_mining", "injectable_urls", []):
            return False
        if phase == "vuln.xss" and not self.state.get_state("recon.param_mining", "param_urls", []):
            return False
        if phase == "vuln.fuzz" and not self.state.get_state("recon.http_probe", "live_urls", []):
            return False

        return True

    def minimize_tool_calls(self, phase: str, targets: list[str]) -> list[str]:
        """Reduce targets to minimum needed. Ponytail: don't scan everything."""
        if not targets:
            return []

        # Cap targets per phase
        caps = {
            "vuln.sqli": 20,
            "vuln.xss": 20,
            "vuln.cors": 10,
            "vuln.redirects": 10,
            "vuln.fuzz": 5,
            "vuln.headers": 10,
            "intel.secrets": 10,
        }
        max_targets = caps.get(phase, 50)
        return targets[:max_targets]

    def combine_steps(self, steps: list[dict]) -> list[dict]:
        """Combine compatible steps. Ponytail: one call instead of many."""
        combined = {}
        for step in steps:
            key = f"{step.get('action')}:{step.get('target')}"
            if key not in combined:
                combined[key] = step
            else:
                # Merge payloads
                existing_payloads = set(combined[key].get("payloads", []))
                new_payloads = set(step.get("payloads", []))
                combined[key]["payloads"] = list(existing_payloads | new_payloads)
        return list(combined.values())

    def prioritize_actions(self, actions: list[str]) -> list[str]:
        """Sort by impact. Ponytail: do high-value things first."""
        priority = {
            "examine_git": 0,
            "read_exposed": 1,
            "test_sqli": 2,
            "test_ssti": 3,
            "test_ssrf": 4,
            "test_xss": 5,
            "test_lfi": 6,
            "test_auth_bypass": 7,
            "test_redirect": 8,
            "test_cors": 9,
            "fuzz": 10,
        }

        def sort_key(action):
            parts = action.split()
            action_type = parts[0] if parts else ""
            return priority.get(action_type, 99)

        return sorted(actions, key=sort_key)

    def generate_minimal_plan(self, state) -> list[str]:
        """Generate the minimum viable attack plan.
        
        Ponytail: What's the least we can do and still find bugs?
        """
        actions = []

        # Always: check exposed files (high value, low effort)
        exposed = state.get_state("intel.secrets", "exposed", [])
        for url in exposed[:5]:
            actions.append(f"read_exposed {url}")

        # Always: check git exposure
        git = state.get_state("intel.secrets", "git_exposed", [])
        for url in git[:3]:
            actions.append(f"examine_git {url}")

        # If params exist: test injectable ones
        injectable = state.get_state("recon.param_mining", "injectable_urls", [])
        for url in injectable[:10]:
            actions.append(f"test_sqli {url}")

        # If API endpoints: test auth
        api = state.get_state("recon.url_discovery", "api_endpoints", [])
        for url in api[:5]:
            actions.append(f"test_auth_bypass {url}")

        return self.prioritize_actions(actions)

    def token_efficient_summary(self, state) -> str:
        """Generate the most token-efficient summary possible.
        
        One line. All key info. No fluff.
        """
        summary = state.summary()
        f = summary.get("findings", {})
        return (
            f"{summary.get('target','')} "
            f"f={summary.get('total_findings',0)} "
            f"c={f.get('critical',0)} h={f.get('high',0)} "
            f"m={f.get('medium',0)} l={f.get('low',0)}"
        )
