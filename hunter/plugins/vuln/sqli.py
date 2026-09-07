"""SQL injection testing with sqlmap."""
from .. import Plugin, Budget
import hashlib


class SQLiPlugin(Plugin):
    name = "vuln.sqli"
    description = "SQL injection detection via sqlmap"
    category = "vuln"
    required_tools = ["sqlmap"]

    def run(self, budget: Budget):
        injectable = self.state.get_state("recon.param_mining", "injectable_urls", [])
        if not injectable:
            self.log("No injectable URLs found", "warn")
            return self.state

        targets = injectable[:self.config.max_targets]
        self.log(f"Testing {len(targets)} URLs for SQLi...")

        findings = []
        for i, url in enumerate(targets):
            self.progress(i, len(targets), "URLs")
            
            # Create unique output dir for this URL
            url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
            out_dir = self.output_dir / url_hash
            out_dir.mkdir(exist_ok=True)

            out = self.run_tool([
                "sqlmap", "-u", url,
                "--batch", "--level=2", "--risk=2",
                "--threads", str(min(budget.threads, 4)),
                "--output-dir", str(out_dir),
                "--smart", "--timeout=10", "--retries=1",
            ], timeout=60)

            if "is vulnerable" in out.lower() or "injectable" in out.lower():
                findings.append(url)
                self.add_finding("sqli", "critical", url, out[:200])
                self.log(f"SQLi FOUND: {url}", "success")

        self.save_lines(findings, str(self.output_dir / "sqli_findings.txt"))
        self.state.set_state(self.name, "findings", findings)
        self.state.set_state(self.name, "tested", len(targets))
        self.log(f"Tested: {len(targets)} | Vulnerable: {len(findings)}")
        return self.state
