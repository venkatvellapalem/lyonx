"""Token-efficient output formats for AI agents.

Minimizes token consumption by:
- Compressed JSON (no nulls, no empty arrays)
- Delta reports (only new/changed findings)
- Pre-summarized results (no raw tool output)
- Compact mode (one-line-per-finding)
"""
import json
from typing import Optional


class CompactEncoder(json.JSONEncoder):
    """JSON encoder that strips nulls, empty strings, and empty containers."""
    def encode(self, o):
        return super().encode(self._compact(o))

    def _compact(self, obj):
        if isinstance(obj, dict):
            return {k: self._compact(v) for k, v in obj.items()
                    if v is not None and v != "" and v != [] and v != {} and v != 0}
        elif isinstance(obj, list):
            compacted = [self._compact(i) for i in obj
                        if i is not None and i != "" and i != [] and i != {}]
            return compacted if compacted else None
        return obj


class TokenEfficient:
    """Generate token-efficient output for agents."""

    @staticmethod
    def compact_json(data: dict) -> str:
        """Minimal JSON — strips nulls, empties, duplicates."""
        return json.dumps(data, cls=CompactEncoder, separators=(',', ':'))

    @staticmethod
    def one_line_summary(state) -> str:
        """One-line scan summary (minimal tokens)."""
        s = state.summary()
        f = s.get("findings", {})
        return (
            f"target={s.get('target','')} "
            f"status={s.get('status','')} "
            f"findings={s.get('total_findings',0)} "
            f"critical={f.get('critical',0)} "
            f"high={f.get('high',0)} "
            f"medium={f.get('medium',0)} "
            f"low={f.get('low',0)}"
        )

    @staticmethod
    def findings_only(state, min_severity: str = "medium") -> list[dict]:
        """Just the findings, no metadata. Sorted by severity."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_val = severity_order.get(min_severity, 2)

        findings = state.get_findings()
        filtered = []
        for f in findings:
            sev_val = severity_order.get(f.severity, 4)
            if sev_val <= min_val:
                filtered.append({
                    "s": f.severity[0].upper(),  # C/H/M/L/I
                    "t": f.type,
                    "u": f.url,
                    "e": f.evidence[:100] if f.evidence else None,
                })
        return sorted(filtered, key=lambda x: severity_order.get(x["s"].lower(), 4))

    @staticmethod
    def action_items(state) -> list[str]:
        """Pre-computed action items for the agent to execute.
        
        Returns concise instructions like:
        - "TEST sqli https://example.com/page?id=1"
        - "CHECK cors https://example.com/api"
        - "FUZZ https://example.com/FUZZ"
        """
        actions = []

        # High-value targets
        injectable = state.get_state("recon.param_mining", "injectable_urls", [])
        for url in injectable[:20]:
            actions.append(f"TEST sqli {url}")

        api_urls = state.get_state("recon.url_discovery", "api_endpoints", [])
        for url in api_urls[:10]:
            actions.append(f"TEST auth_bypass {url}")
            actions.append(f"TEST idor {url}")

        param_urls = state.get_state("recon.param_mining", "param_urls", [])
        for url in param_urls[:10]:
            actions.append(f"TEST xss {url}")

        redirect_urls = state.get_state("recon.param_mining", "redirect_urls", [])
        for url in redirect_urls[:5]:
            actions.append(f"TEST open_redirect {url}")

        exposed = state.get_state("intel.secrets", "exposed", [])
        for url in exposed[:5]:
            actions.append(f"READ {url}")

        git_exposed = state.get_state("intel.secrets", "git_exposed", [])
        for url in git_exposed[:3]:
            actions.append(f"CLONE {url}")

        live_urls = state.get_state("recon.http_probe", "live_urls", [])
        for url in live_urls[:5]:
            actions.append(f"FUZZ {url}/FUZZ")

        return actions

    @staticmethod
    def delta_report(current_state, previous_state) -> dict:
        """Delta between two scans — only new/changed findings."""
        current_findings = {f.url: f for f in current_state.get_findings()}
        previous_findings = {f.url: f for f in previous_state.get_findings()}

        new = []
        changed = []
        gone = []

        for url, f in current_findings.items():
            if url not in previous_findings:
                new.append({"s": f.severity, "t": f.type, "u": url})
            elif previous_findings[url].severity != f.severity:
                changed.append({"s": f.severity, "t": f.type, "u": url, "was": previous_findings[url].severity})

        for url, f in previous_findings.items():
            if url not in current_findings:
                gone.append({"s": f.severity, "t": f.type, "u": url})

        return {"new": new, "changed": changed, "gone": gone}

    @staticmethod
    def agent_prompt(state) -> str:
        """Generate a concise prompt for an AI agent to continue analysis.
        
        Minimizes tokens by pre-filtering and structuring data.
        """
        summary = state.summary()
        findings = TokenEfficient.findings_only(state, "medium")
        actions = TokenEfficient.action_items(state)

        lines = [
            f"Scan of {summary.get('target', '')}: {summary.get('total_findings', 0)} findings.",
        ]

        if findings:
            lines.append("Key findings:")
            for f in findings[:15]:
                lines.append(f"  [{f['s']}] {f['t']}: {f['u']}")

        if actions:
            lines.append("Suggested actions:")
            for a in actions[:15]:
                lines.append(f"  {a}")

        return "\n".join(lines)
