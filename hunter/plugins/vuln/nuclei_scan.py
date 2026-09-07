"""Nuclei vulnerability scanning plugin."""
import json
import re
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

        # Run nuclei with jsonl output and severity filtering
        out = self.run_pipe(input_data, [
            "nuclei", "-silent",
            "-severity", "critical,high,medium",
            "-c", str(budget.threads),
            "-jsonl",
        ], timeout=900)

        lines = [l.strip() for l in out.splitlines() if l.strip()]
        self.save_lines(lines, str(self.output_dir / "nuclei_results.jsonl"))

        critical = []
        high = []
        medium = []

        for line in lines:
            parsed = self._parse_nuclei_line(line)
            if not parsed:
                continue
            
            sev = parsed.get("severity", "medium").lower()
            url = parsed.get("url", "")
            template_id = parsed.get("template_id", "nuclei")
            evidence = parsed.get("evidence", line)

            if sev == "critical":
                critical.append(line)
                self.add_finding(f"nuclei.{template_id}", "critical", url, evidence)
            elif sev == "high":
                high.append(line)
                self.add_finding(f"nuclei.{template_id}", "high", url, evidence)
            elif sev == "medium":
                medium.append(line)
                self.add_finding(f"nuclei.{template_id}", "medium", url, evidence)

        self.save_lines(critical, str(self.output_dir / "critical.txt"))
        self.save_lines(high, str(self.output_dir / "high.txt"))
        self.save_lines(medium, str(self.output_dir / "medium.txt"))

        # Also scan JS files
        js_urls = self.state.get_state("recon.url_discovery", "js_urls", [])
        if js_urls:
            self.log(f"Running nuclei on {len(js_urls)} JS files...")
            js_input = "\n".join(js_urls[:50])
            js_out = self.run_pipe(js_input, [
                "nuclei", "-silent", "-tags", "js", "-c", str(budget.threads), "-jsonl"
            ], timeout=300)
            js_lines = [l.strip() for l in js_out.splitlines() if l.strip()]
            self.save_lines(js_lines, str(self.output_dir / "nuclei_js.jsonl"))
            for line in js_lines:
                parsed = self._parse_nuclei_line(line)
                if parsed:
                    self.add_finding(f"nuclei.{parsed.get('template_id','js')}", "medium", parsed.get("url", ""), parsed.get("evidence", line))

        self.state.set_state(self.name, "critical", len(critical))
        self.state.set_state(self.name, "high", len(high))
        self.state.set_state(self.name, "medium", len(medium))
        self.log(f"Findings: Critical={len(critical)} High={len(high)} Medium={len(medium)}")
        return self.state

    def _parse_nuclei_line(self, line: str) -> dict:
        """Parse nuclei output either from JSON or standard text format."""
        try:
            data = json.loads(line)
            url = data.get("matched-at") or data.get("host") or data.get("url", "")
            template_id = data.get("template-id") or data.get("template", "nuclei")
            severity = data.get("info", {}).get("severity") or "medium"
            extracted = data.get("extracted-results", [])
            evidence = str(extracted) if extracted else data.get("matcher-name", "") or line[:200]
            return {"url": url, "template_id": template_id, "severity": severity, "evidence": evidence}
        except (json.JSONDecodeError, TypeError):
            url_match = re.search(r'https?://[^\s\[\]]+', line)
            url = url_match.group(0) if url_match else ""
            template_match = re.search(r'\[([^\]]+)\]', line)
            template_id = template_match.group(1) if template_match else "nuclei"
            sev = "medium"
            if "critical" in line.lower(): sev = "critical"
            elif "high" in line.lower(): sev = "high"
            return {"url": url, "template_id": template_id, "severity": sev, "evidence": line[:200]}
