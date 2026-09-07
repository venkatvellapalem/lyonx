"""Nuclei vulnerability scanning plugin."""
from .. import Plugin, Budget


class NucleiPlugin(Plugin):
    name = "vuln.nuclei"
    description = "Template-based vulnerability scanning (13,949 templates)"
    category = "vuln"
    required_tools = ["nuclei"]

    def run(self, budget: Budget):
        live_urls = self.state.get_state("recon.http_probe", "live_urls", [])
        if not live_urls:
            self.log("No live URLs to scan", "warn")
            return self.state

        self.log(f"Running nuclei on {len(live_urls)} URLs...")
        input_data = "\n".join(live_urls)

        # Run nuclei with severity filtering
        out = self.run_pipe(input_data, [
            "nuclei", "-silent",
            "-severity", "critical,high,medium",
            "-c", str(budget.threads),
            "-stats",
        ], timeout=900)

        findings = [l.strip() for l in out.splitlines() if l.strip()]
        self.save_lines(findings, str(self.output_dir / "nuclei_results.txt"))

        # Categorize by severity
        critical = [f for f in findings if "critical" in f.lower()]
        high = [f for f in findings if "high" in f.lower()]
        medium = [f for f in findings if "medium" in f.lower()]

        self.save_lines(critical, str(self.output_dir / "critical.txt"))
        self.save_lines(high, str(self.output_dir / "high.txt"))
        self.save_lines(medium, str(self.output_dir / "medium.txt"))

        # Register findings
        for f in critical:
            self.add_finding("nuclei", "critical", f.split()[0] if f.split() else "", f)
        for f in high:
            self.add_finding("nuclei", "high", f.split()[0] if f.split() else "", f)
        for f in medium:
            self.add_finding("nuclei", "medium", f.split()[0] if f.split() else "", f)

        # Also scan JS files
        js_urls = self.state.get_state("recon.url_discovery", "js_urls", [])
        if js_urls:
            self.log(f"Running nuclei on {len(js_urls)} JS files...")
            js_input = "\n".join(js_urls[:50])
            js_out = self.run_pipe(js_input, [
                "nuclei", "-silent", "-tags", "js", "-c", str(budget.threads)
            ], timeout=300)
            js_findings = [l.strip() for l in js_out.splitlines() if l.strip()]
            self.save_lines(js_findings, str(self.output_dir / "nuclei_js.txt"))
            for f in js_findings:
                self.add_finding("nuclei_js", "medium", f.split()[0] if f.split() else "", f)

        self.state.set_state(self.name, "critical", len(critical))
        self.state.set_state(self.name, "high", len(high))
        self.state.set_state(self.name, "medium", len(medium))
        self.log(f"Findings: Critical={len(critical)} High={len(high)} Medium={len(medium)}")
        return self.state
