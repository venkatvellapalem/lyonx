"""XSS scanning with dalfox."""
import json
import re
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
            "--format", "json",
            "-o", str(self.output_dir / "xss_findings.json")
        ], timeout=600)

        findings = [l.strip() for l in out.splitlines() if l.strip()] if out else []
        if not findings:
            findings = self.file_lines(str(self.output_dir / "xss_findings.json"))

        for f in findings:
            url = ""
            evidence = f
            try:
                data = json.loads(f)
                url = data.get("url") or data.get("data", "")
                param = data.get("param", "")
                evidence = f"Param: {param} | Payload: {data.get('payload', '')}"
            except (json.JSONDecodeError, TypeError):
                url_match = re.search(r'https?://[^\s]+', f)
                url = url_match.group(0) if url_match else ""

            if url:
                self.add_finding("xss", "high", url, evidence)

        self.save_lines(findings, str(self.output_dir / "xss_findings.txt"))
        self.state.set_state(self.name, "findings", findings)
        self.log(f"XSS findings: {len(findings)}")
        return self.state
