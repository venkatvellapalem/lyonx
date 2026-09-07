"""Final report generation."""
from .. import Plugin, Budget
from datetime import datetime


class ReportPlugin(Plugin):
    name = "post.report"
    description = "Generate final markdown report"
    category = "post"

    def run(self, budget: Budget):
        self.log("Generating final report...")

        import sqlite3
        conn = sqlite3.connect(str(self.state.db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT target, started_at, completed_at FROM scans WHERE id = ?",
                          (self.state.scan_id,)).fetchone()
        target = row["target"] if row else ""
        started = row["started_at"] if row else 0
        completed = row["completed_at"] if row else 0
        conn.close()

        findings = self.state.get_findings()
        summary = self.state.summary()

        sub_count = self.state.get_state("recon.subdomains", "count", 0)
        live_count = self.state.get_state("recon.http_probe", "live_count", 0)
        port_count = self.state.get_state("recon.ports", "count", 0)
        url_count = len(self.state.get_state("recon.url_discovery", "all_urls", []))
        param_count = len(self.state.get_state("recon.param_mining", "param_urls", []))
        api_count = len(self.state.get_state("recon.url_discovery", "api_endpoints", []))
        js_count = len(self.state.get_state("recon.url_discovery", "js_urls", []))
        sqli_count = len(self.state.get_state("vuln.sqli", "findings", []))
        xss_count = len(self.state.get_state("vuln.xss", "findings", []))
        cors_count = len(self.state.get_state("vuln.cors", "findings", []))
        redir_count = len(self.state.get_state("vuln.redirects", "findings", []))
        exposed_count = len(self.state.get_state("intel.secrets", "exposed", []))
        nuclei_crit = self.state.get_state("vuln.nuclei", "critical", 0)
        nuclei_high = self.state.get_state("vuln.nuclei", "high", 0)
        nuclei_med = self.state.get_state("vuln.nuclei", "medium", 0)

        elapsed = (completed - started) if completed and started else 0
        findings_by_sev = summary.get("findings", {})

        report = f"""# Bug Bounty Report: {target}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Scan ID:** {self.state.scan_id}
**Duration:** {elapsed:.0f}s
**Engine:** Hunter v3

---

## Executive Summary

| Metric | Count | Status |
|--------|-------|--------|
| Subdomains | {sub_count} | {'✅' if sub_count > 0 else '⚠️'} |
| Live Hosts | {live_count} | {'✅' if live_count > 0 else '⚠️'} |
| Open Ports | {port_count} | ✅ |
| URLs Found | {url_count} | ✅ |
| Parameters | {param_count} | ✅ |
| API Endpoints | {api_count} | ✅ |
| JS Files | {js_count} | ✅ |
| **Critical** | {findings_by_sev.get('critical', 0)} | {'🔴' if findings_by_sev.get('critical', 0) > 0 else '✅'} |
| **High** | {findings_by_sev.get('high', 0)} | {'🟠' if findings_by_sev.get('high', 0) > 0 else '✅'} |
| **Medium** | {findings_by_sev.get('medium', 0)} | {'🟡' if findings_by_sev.get('medium', 0) > 0 else '✅'} |
| **Low** | {findings_by_sev.get('low', 0)} | ✅ |

---

## Vulnerability Findings

### Nuclei Scan
- Critical: {nuclei_crit}
- High: {nuclei_high}
- Medium: {nuclei_med}

### SQL Injection
{sqli_count} findings
{chr(10).join('- ' + f.url for f in self.state.get_findings('critical', 'sqli')[:10]) or 'None found'}

### XSS
{xss_count} findings
{chr(10).join('- ' + f.url for f in self.state.get_findings('high', 'xss')[:10]) or 'None found'}

### CORS Misconfigurations
{cors_count} findings
{chr(10).join('- ' + f.url for f in self.state.get_findings() if f.type == 'cors') or 'None found'}

### Open Redirects
{redir_count} findings

### Exposed Files
{exposed_count} findings

---

## Key Files

| File | Description |
|------|-------------|
| `post/prioritize/manual_targets.md` | **Start here** — prioritized targets |
| `recon/http_probe/live_urls.txt` | All live URLs |
| `recon/url_discovery/all_urls.txt` | All discovered URLs |
| `recon/url_discovery/api_endpoints.txt` | API endpoints |
| `recon/param_mining/injectable_urls.txt` | Injectable parameters |
| `recon/ports/open_ports.txt` | Open ports |
| `vuln/nuclei_scan/nuclei_results.txt` | Nuclei findings |
| `vuln/sqli/sqli_findings.txt` | SQLi findings |
| `vuln/xss/xss_findings.txt` | XSS findings |
| `intel/secrets/exposed_files.txt` | Exposed files |

---

## Manual Testing Guide

See `post/prioritize/manual_targets.md` for the full prioritized list.

### What to test manually:
1. **IDOR** — Check API endpoints for IDOR (swap IDs, test access control)
2. **Auth Bypass** — Test auth endpoints without tokens, with expired tokens
3. **Business Logic** — Test price manipulation, race conditions, workflow bypass
4. **Parameter Tampering** — Modify parameters in injectable URLs
5. **Broken Access Control** — Test horizontal/vertical privilege escalation
"""

        self.save_text(report, str(self.output_dir.parent / "report.md"))
        self.log(f"Report saved to {self.output_dir.parent / 'report.md'}")
        return self.state
