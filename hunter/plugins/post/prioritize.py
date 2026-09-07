"""Finding prioritization — generates manual testing targets."""
from .. import Plugin, Budget


class PrioritizePlugin(Plugin):
    name = "post.prioritize"
    description = "AI-powered finding prioritization and manual targets"
    category = "post"

    def run(self, budget: Budget):
        self.log("Prioritizing findings and generating manual targets...")

        findings = self.state.get_findings()
        
        # Categorize by severity and exploitability
        critical = [f for f in findings if f.severity == "critical"]
        high = [f for f in findings if f.severity == "high"]
        medium = [f for f in findings if f.severity == "medium"]
        low = [f for f in findings if f.severity == "low"]

        # Get data for manual targets
        injectable_urls = self.state.get_state("recon.param_mining", "injectable_urls", [])
        api_endpoints = self.state.get_state("recon.url_discovery", "api_endpoints", [])
        param_urls = self.state.get_state("recon.param_mining", "param_urls", [])
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        js_endpoints = self.state.get_state("recon.js_analysis", "endpoints", [])
        exposed = self.state.get_state("intel.secrets", "exposed", [])
        git_exposed = self.state.get_state("intel.secrets", "git_exposed", [])
        cors_issues = self.state.get_state("vuln.cors", "findings", [])
        redirect_issues = self.state.get_state("vuln.redirects", "findings", [])
        takeover_candidates = self.state.get_state("intel.takeover", "candidates", [])
        ports = self.state.get_state("recon.ports", "interesting", [])
        missing_headers = self.state.get_state("vuln.headers", "missing", [])

        # Build prioritized manual targets
        lines = [
            "# Manual Testing Targets",
            "",
            "## Priority Legend",
            "- 🔴 HIGH = Likely exploitable, test first",
            "- 🟡 MEDIUM = Interesting, test after high priority",
            "- 🟢 LOW = Informational",
            "",
            "---",
            "",
            "## 🔴 HIGH PRIORITY",
            "",
            "### Automated Findings (Critical/High)",
        ]

        for f in critical + high:
            lines.append(f"- [{f.severity.upper()}] {f.type}: {f.url}")
            if f.evidence:
                lines.append(f"  Evidence: {f.evidence[:200]}")

        lines.extend(["", "### Manual SQLi/XSS Testing (URLs with injectable params)"])
        for url in injectable_urls[:50]:
            lines.append(f"- {url}")

        lines.extend(["", "### Manual IDOR/Auth Testing (API Endpoints)"])
        for ep in api_endpoints[:30]:
            lines.append(f"- {ep}")

        lines.extend(["", "### Exposed Files"])
        for f in exposed[:20]:
            lines.append(f"- {f}")

        lines.extend(["", "### .git Exposures"])
        for f in git_exposed[:10]:
            lines.append(f"- {f}")

        lines.extend(["", "### CORS Issues"])
        for f in cors_issues[:10]:
            lines.append(f"- {f}")

        lines.extend(["", "### Open Redirects"])
        for f in redirect_issues[:10]:
            lines.append(f"- {f}")

        lines.extend(["", "### Subdomain Takeover Candidates"])
        for f in takeover_candidates[:10]:
            lines.append(f"- {f}")

        lines.extend(["", "---", "", "## 🟡 MEDIUM PRIORITY", ""])
        lines.append("### Interesting Ports")
        for p in ports[:20]:
            lines.append(f"- {p}")

        lines.extend(["", "### URLs with Parameters (test for IDOR, injection)"])
        for url in param_urls[:50]:
            lines.append(f"- {url}")

        lines.extend(["", "### JS Extracted Endpoints"])
        for ep in js_endpoints[:30]:
            lines.append(f"- {ep}")

        lines.extend(["", "### Missing Security Headers"])
        for h in missing_headers[:20]:
            lines.append(f"- {h}")

        lines.extend(["", "---", "", "## 🟢 LOW PRIORITY", ""])
        lines.append("### All Live URLs")
        for url in live_urls[:50]:
            lines.append(f"- {url}")

        # Write manual targets
        self.save_text("\n".join(lines), str(self.output_dir / "manual_targets.md"))
        self.log(f"Generated manual_targets.md with {len(findings)} findings prioritized")
        return self.state
