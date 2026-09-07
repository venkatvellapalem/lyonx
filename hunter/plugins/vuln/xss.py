"""XSS scanning with dalfox."""
from .. import Plugin, Budget


class XSSPlugin(Plugin):
    name = "vuln.xss"
    description = "XSS detection via dalfox"
    category = "vuln"
    required_tools = ["dalfox"]

    def run(self, budget: Budget):
        param_urls = self.state.get_state("recon.param_mining", "param_urls", [])
        if not param_urls:
            self.log("No parameter URLs for XSS testing", "warn")
            return self.state

        targets = param_urls[:self.config.max_targets]
        self.log(f"Testing {len(targets)} URLs for XSS...")

        input_data = "\n".join(targets)
        out = self.run_pipe(input_data, [
            "dalfox", "pipe", "--silence", "--skip-bav",
            "-o", str(self.output_dir / "xss_findings.txt")
        ], timeout=600)

        findings = [l.strip() for l in out.splitlines() if l.strip()] if out else []
        
        # Read the output file if pipe didn't capture
        if not findings:
            findings = self.file_lines(str(self.output_dir / "xss_findings.txt"))

        for f in findings:
            self.add_finding("xss", "high", f.split()[0] if f.split() else "", f)

        self.state.set_state(self.name, "findings", findings)
        self.log(f"XSS findings: {len(findings)}")
        return self.state
